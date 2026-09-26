package probe

import (
	"strings"
	"testing"

	"github.com/dcyber-lab/reachable/internal/node"
)

// Probes from A (10.0.0.1) to B (10.0.0.2) tcp/80; each case is one place
// a probe can die and what the two observations look like when it does.

var capture = node.Inventory{Have: []string{"capture"}}

func syn(dir string) node.Packet {
	return node.Packet{Dir: dir, Proto: "tcp", Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Flags: "S"}
}

func synack(dir string) node.Packet {
	return node.Packet{Dir: dir, Proto: "tcp", Src: "10.0.0.2", SrcPort: 80, Dst: "10.0.0.1", DstPort: 40000, Flags: "S."}
}

func obsSide(label string, inv node.Inventory, pk []node.Packet, drops []node.Drop, ctrs []node.Counter) side {
	return side{label: label, ok: true, inv: inv, obs: node.Observed{Packets: pk, Drops: drops, Counters: ctrs}}
}

func TestAnalyze(t *testing.T) {
	sent := []node.Packet{syn("Out"), syn("Out")}
	arrived := []node.Packet{syn("In"), syn("In")}
	cases := []struct {
		name                       string
		a, b                       side
		dials                      []node.Dial
		where, mech, conf, culprit string
	}{
		{"A's tc egress, by counter",
			obsSide("A", capture, nil, nil, []node.Counter{{Kind: "tc", Scope: "eth0", Name: "clsact", Delta: 6}}),
			obsSide("B", capture, nil, nil, nil), nil,
			whereSrcEgress, "tc", counted, "tc clsact on eth0"},
		{"A's OUTPUT rule, by drop trace",
			obsSide("A", capture, nil, []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "nft_do_chain", Reason: "NETFILTER_DROP"}}, nil),
			obsSide("B", capture, nil, nil, nil), nil,
			whereSrcEgress, "netfilter", observed, "NETFILTER_DROP"},
		{"connect refused locally (cgroup connect4, LSM)",
			obsSide("A", capture, nil, nil, nil), obsSide("B", capture, nil, nil, nil),
			[]node.Dial{{Outcome: node.Failed, Msg: "Operation not permitted"}},
			whereSrcEgress, "local_policy", observed, "connect() refused locally"},
		{"network ACL, by elimination",
			obsSide("A", capture, sent, nil, nil), obsSide("B", capture, nil, nil, nil), nil,
			wherePath, "network", inferred, "security group"},
		{"router answers with ICMP admin prohibited",
			obsSide("A", capture, append(sent, node.Packet{Proto: "icmp", Src: "10.0.0.254", Dst: "10.0.0.1", Info: "ICMP host 10.0.0.2 unreachable - admin prohibited filter"}), nil, nil),
			obsSide("B", capture, nil, nil, nil), nil,
			wherePath, "network_reject", observed, "10.0.0.254 answered"},
		{"generic XDP on B, by drop trace",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, nil, []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "netif_receive_generic_xdp"}}, nil), nil,
			whereDstXDP, "xdp", observed, "no reason on this kernel"},
		{"native XDP on B, by driver counter",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, nil, nil, []node.Counter{{Kind: "nic", Scope: "eth0", Name: "rx_xdp_drop", Delta: 6}}), nil,
			whereDstXDP, "xdp", counted, "eth0 rx_xdp_drop +6"},
		{"native XDP on B, no evidence either way",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", node.Inventory{Have: []string{"capture"}, Hooks: []node.Hook{{Kind: "xdp", Where: "eth0", Detail: "native id 42"}}}, nil, nil, nil), nil,
			whereUnknown, "xdp_or_network", inferred, "XDP on B's eth0"},
		{"B's NIC ring overflow",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, nil, nil, []node.Counter{{Kind: "nic", Scope: "eth0", Name: "rx_missed_errors", Delta: 6}}), nil,
			whereDstNIC, "nic", counted, "rx_missed_errors"},
		{"B's tc ingress program, by drop trace",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, arrived, []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "__netif_receive_skb_core", Reason: "TC_INGRESS"}}, nil), nil,
			whereDstIngress, "tc", observed, "TC_INGRESS"},
		{"B's tc program on a kernel without drop reasons",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, arrived, []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "__netif_receive_skb_core"}},
				[]node.Counter{{Kind: "tc", Scope: "eth0", Name: "clsact", Delta: 6}}), nil,
			whereDstIngress, "tc", observed, "tc clsact on eth0 dropped 6"},
		{"B's iptables rule, by counter (old kernel, no trace)",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, arrived, nil, []node.Counter{
				{Kind: "nic", Scope: "eth0", Name: "rx_dropped", Baseline: 40, Delta: 45}, // background noise
				{Kind: "fw", Scope: "iptables-save filter", Name: "-A INPUT -p tcp --dport 80 -j DROP", Delta: 6}}), nil,
			whereDstIngress, "netfilter", counted, "-A INPUT -p tcp --dport 80 -j DROP"},
		{"B's rp_filter",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, arrived, nil, []node.Counter{{Kind: "stat", Scope: "TcpExt", Name: "IPReversePathFilter", Delta: 6}}), nil,
			whereDstIngress, "rp_filter", counted, "reverse path filter"},
		{"B's listen queue overflows",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, arrived, nil, []node.Counter{{Kind: "stat", Scope: "TcpExt", Name: "ListenOverflows", Delta: 6}}), nil,
			whereDstIngress, "listen_queue", counted, "accepting"},
		{"B's stack, nothing says what",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", node.Inventory{Have: []string{"capture"}, Hooks: []node.Hook{{Kind: "cgroup", Where: "cgroup_inet_ingress", Detail: "1 program(s)"}}}, arrived, nil, nil), nil,
			whereDstIngress, "unknown", inferred, "cgroup on cgroup_inet_ingress"},
		{"B's tc egress eats the SYN-ACK",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, arrived, []node.Drop{{Src: "10.0.0.2", SrcPort: 80, Dst: "10.0.0.1", DstPort: 40000, Location: "__dev_queue_xmit", Reason: "TC_EGRESS"}}, nil), nil,
			whereDstEgress, "tc", observed, "TC_EGRESS"},
		{"reply lost on the way back",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, append(arrived, synack("Out")), nil, nil), nil,
			whereReturnPath, "network", inferred, "asymmetric routing"},
		{"reply lost on the way back, B drops the retried SYNs as it should",
			obsSide("A", capture, sent, nil, nil),
			obsSide("B", capture, append(arrived, synack("Out")), []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "tcp_v4_rcv", Reason: "NOT_SPECIFIED"}}, nil), nil,
			whereReturnPath, "network", inferred, "asymmetric routing"},
		{"reply reaches A, A's firewall drops it",
			obsSide("A", capture, append(sent, synack("In")), nil, []node.Counter{{Kind: "fw", Scope: "iptables-save filter", Name: "-A INPUT -s 10.0.0.2 -j DROP", Delta: 3}}),
			obsSide("B", capture, append(arrived, synack("Out")), nil, nil), nil,
			whereSrcIngress, "netfilter", counted, "-A INPUT -s 10.0.0.2 -j DROP"},
		{"something else answers for B",
			obsSide("A", capture, append(sent, synack("In")), nil, nil),
			obsSide("B", capture, nil, nil, nil), nil,
			wherePath, "intercepted", observed, "never received a probe"},
		{"a drop in a container's namespace on A is not A's",
			obsSide("A", capture, sent, []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "nft_do_chain", Reason: "NETFILTER_DROP", OtherNetns: true}}, nil),
			obsSide("B", capture, arrived, []node.Drop{{Src: "10.0.0.1", SrcPort: 40000, Dst: "10.0.0.2", DstPort: 80, Location: "nft_do_chain", Reason: "NETFILTER_DROP"}}, nil), nil,
			whereDstIngress, "netfilter", observed, "NETFILTER_DROP"},
		{"only B observable, counters only",
			side{label: "A", why: "needs root or passwordless sudo"},
			obsSide("B", node.Inventory{}, nil, nil, []node.Counter{{Kind: "fw", Scope: "iptables-save filter", Name: ":INPUT DROP policy", Delta: 6}}), nil,
			whereUnknown, "netfilter", counted, "INPUT DROP"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := analyze(node.TCP, 80, "10.0.0.2", c.a, c.b, c.dials)
			if f.where != c.where || f.mechanism != c.mech || f.confidence != c.conf || !strings.Contains(f.culprit, c.culprit) {
				t.Errorf("got where=%s mechanism=%s confidence=%s culprit=%q\nwant where=%s mechanism=%s confidence=%s culprit~%q\nevidence:\n  %s",
					f.where, f.mechanism, f.confidence, f.culprit, c.where, c.mech, c.conf, c.culprit, strings.Join(f.evidence, "\n  "))
			}
		})
	}
}

func TestLocateWiring(t *testing.T) {
	drop := map[string]node.Dial{"tcp/80": {Outcome: node.Timeout}}

	// Neither side can observe: one skip, and the port verdict stands.
	d := run(t, &fake{route: up, ping: pingOK, dial: drop}, &fake{}, Options{TCPPorts: []int{80}, Locate: true})
	if codes(d)["locate tcp/80"] != "locate.unsupported" || codes(d)["tcp/80"] != "tcp.dropped" {
		t.Errorf("unsupported: %v", codes(d))
	}

	// Both can: the finding lands as its own check with the structured fields.
	a := &fakeObservation{inv: capture, obs: node.Observed{Packets: []node.Packet{syn("Out")}}}
	b := &fakeObservation{inv: capture, obs: node.Observed{Packets: []node.Packet{syn("In")},
		Counters: []node.Counter{{Kind: "fw", Scope: "iptables-save filter", Name: "-A INPUT -p tcp --dport 80 -j DROP", Delta: 3}}}}
	d = run(t, &fake{route: up, ping: pingOK, dial: drop, observe: a}, &fake{observe: b}, Options{TCPPorts: []int{80}, Locate: true})
	var c Check
	for _, x := range d.Checks {
		if x.Name == "locate tcp/80" {
			c = x
		}
	}
	if c.Code != "drop.dst_ingress" || c.Where != whereDstIngress || c.Mechanism != "netfilter" ||
		c.Confidence != counted || !strings.Contains(c.Culprit, "--dport 80 -j DROP") || len(c.Lines) == 0 {
		t.Errorf("locate check: %+v", c)
	}

	// Open ports aren't located.
	d = run(t, &fake{route: up, ping: pingOK, dial: map[string]node.Dial{"tcp/80": {Outcome: node.Open}}, observe: a},
		&fake{observe: b, peer: map[string]string{"tcp/80": "10.0.0.1"}}, Options{TCPPorts: []int{80}, Locate: true})
	if _, ok := codes(d)["locate tcp/80"]; ok {
		t.Errorf("located an open port: %v", codes(d))
	}
}
