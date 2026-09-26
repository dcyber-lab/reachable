package shell

import (
	"errors"
	"testing"

	"github.com/dcyber-lab/reachable/internal/node"
)

func TestParsePacket(t *testing.T) {
	cases := []struct {
		line string
		want node.Packet
	}{
		{"1790392127.309615 dB    In  IP 10.9.0.1.51878 > 10.9.0.2.8080: Flags [S], seq 975842383, win 64240, length 0",
			node.Packet{Time: 1790392127.309615, Dev: "dB", Dir: "In", Proto: "tcp", Src: "10.9.0.1", SrcPort: 51878, Dst: "10.9.0.2", DstPort: 8080, Flags: "S"}},
		{"1790392127.5 IP 10.9.0.2.8080 > 10.9.0.1.51878: Flags [S.], seq 1, ack 2, win 65160, length 0",
			node.Packet{Time: 1790392127.5, Proto: "tcp", Src: "10.9.0.2", SrcPort: 8080, Dst: "10.9.0.1", DstPort: 51878, Flags: "S."}},
		{"1.0 dA Out IP 10.9.0.1.40000 > 10.9.0.2.5353: UDP, length 16",
			node.Packet{Time: 1, Dev: "dA", Dir: "Out", Proto: "udp", Src: "10.9.0.1", SrcPort: 40000, Dst: "10.9.0.2", DstPort: 5353}},
		{"2.0 IP 10.9.0.254 > 10.9.0.1: ICMP host 10.9.0.2 unreachable - admin prohibited filter, length 72",
			node.Packet{Time: 2, Proto: "icmp", Src: "10.9.0.254", Dst: "10.9.0.1", Info: "ICMP host 10.9.0.2 unreachable - admin prohibited filter"}},
		{"3.0 dB In IP6 fd00:9::1.51878 > fd00:9::2.8080: Flags [R.], seq 0, ack 1, win 0, length 0",
			node.Packet{Time: 3, Dev: "dB", Dir: "In", Proto: "tcp", Src: "fd00:9::1", SrcPort: 51878, Dst: "fd00:9::2", DstPort: 8080, Flags: "R."}},
	}
	for _, c := range cases {
		got, ok := parsePacket(c.line)
		if !ok || got != c.want {
			t.Errorf("parsePacket(%q)\n got %+v %v\nwant %+v", c.line, got, ok, c.want)
		}
	}
	if _, ok := parsePacket("tcpdump: listening on any"); ok {
		t.Error("parsed a non-packet line")
	}
}

func TestParseObserve(t *testing.T) {
	inv, dir, err := parseObserveStart("dir=/tmp/reachable-obs.x\nkernel=6.1.0\n" +
		"hook=xdp\teth0\tnative id 42\nhook=tc-ingress\teth0\tbpf cls_main id 7\n" +
		"rpf=all 1\nct=10 262144\nfw=iptables-save filter INPUT policy DROP\n" +
		"have=capture\nmissing=droptrace: no bpftrace\nready=1\n")
	if err != nil || dir != "/tmp/reachable-obs.x" {
		t.Fatalf("start: %v %q", err, dir)
	}
	if len(inv.Hooks) != 2 || inv.Hooks[0] != (node.Hook{Kind: "xdp", Where: "eth0", Detail: "native id 42"}) ||
		inv.RPFilter["all"] != 1 || inv.ConntrackMax != 262144 || len(inv.Policies) != 1 ||
		len(inv.Have) != 1 || len(inv.Missing) != 1 {
		t.Fatalf("inventory %+v", inv)
	}
	if _, _, err := parseObserveStart("err=needs root or passwordless sudo\n"); !errors.Is(err, node.ErrUnsupported) {
		t.Fatalf("not root: %v", err)
	}

	o, err := parseObserveStop("window=2.10 4.35\n" +
		"ctr=fw\tiptables-save filter\t-A INPUT -p tcp -m tcp --dport 8080 -j DROP\t0\t6\n" +
		"ctr=tc\teth0\tclsact\t1\t7\n" +
		"pkt=1.0 eth0 In IP 10.0.0.1.4000 > 10.0.0.2.8080: Flags [S], length 0\n" +
		"drop=10.0.0.1 4000 10.0.0.2 8080 nft_do_chain NETFILTER_DROP here\n" +
		"drop=10.0.0.1 4001 10.0.0.2 8080 netif_receive_generic_xdp - other\n")
	if err != nil || len(o.Counters) != 2 || len(o.Packets) != 1 || len(o.Drops) != 2 {
		t.Fatalf("stop: %v %+v", err, o)
	}
	if o.BaselineSecs != 2.1 || o.ProbeSecs != 4.35 {
		t.Errorf("windows %v %v", o.BaselineSecs, o.ProbeSecs)
	}
	if o.Counters[1] != (node.Counter{Kind: "tc", Scope: "eth0", Name: "clsact", Baseline: 1, Delta: 7}) {
		t.Errorf("counter %+v", o.Counters[1])
	}
	if o.Drops[0].Reason != "NETFILTER_DROP" || o.Drops[0].OtherNetns || o.Drops[1].Reason != "" ||
		o.Drops[1].Location != "netif_receive_generic_xdp" || !o.Drops[1].OtherNetns {
		t.Errorf("drops %+v", o.Drops)
	}
}
