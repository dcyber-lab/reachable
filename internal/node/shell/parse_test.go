package shell

import (
	"testing"

	"github.com/dcyber-lab/reachable/internal/node"
)

func TestParsePing(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want node.Ping
		ok   bool
	}{
		{"iputils all replies", `PING 10.9.0.2 (10.9.0.2) 56(84) bytes of data.
--- 10.9.0.2 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 816ms
rtt min/avg/max/mdev = 0.031/0.045/0.061/0.010 ms`, node.Ping{Sent: 5, Received: 5, AvgMS: 0.045}, true},
		{"iputils loss", `5 packets transmitted, 2 received, 60% packet loss, time 4ms
rtt min/avg/max/mdev = 1.0/2.5/4.0/1.0 ms`, node.Ping{Sent: 5, Received: 2, AvgMS: 2.5}, true},
		{"busybox", `5 packets transmitted, 0 packets received, 100% packet loss`, node.Ping{Sent: 5}, true},
		{"not permitted", `ping: socket: Operation not permitted`, node.Ping{}, false},
	}
	for _, c := range cases {
		got, ok := parsePing(c.out)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestParseConnect(t *testing.T) {
	cases := []struct {
		out  string
		want node.Outcome
	}{
		{"rc=0\nms=3\nerr=\n", node.Open},
		{"rc=124\nms=3001\nerr=\n", node.Timeout},
		{"rc=1\nms=1\nerr=bash: line 1: /dev/tcp/10.0.0.1/80: Connection refused\n", node.Refused},
		{"rc=1\nms=1\nerr=bash: line 1: /dev/tcp/10.0.0.1/80: No route to host\n", node.Unreachable},
		{"rc=1\nms=1\nerr=bash: connect: Network is unreachable\n", node.Unreachable},
		{"rc=1\nms=1\nerr=bash: example.invalid: Name or service not known\n", node.Failed},
		{"", node.Failed},
	}
	for _, c := range cases {
		if got := parseConnect(c.out); got.Outcome != c.want {
			t.Errorf("parseConnect(%q) = %s, want %s", c.out, got.Outcome, c.want)
		}
	}
}

func TestParseUDP(t *testing.T) {
	cases := []struct {
		out  string
		want node.Outcome
	}{
		{"sent=1\nreply=pong\nerr=\n", node.Open},
		{"sent=1\nreply=none\nerr=\n", node.Timeout},
		{"sent=1\nreply=none\nerr=Connection refused\n", node.Refused},
		{"sent=0\nreply=none\nerr=could not open a UDP socket\n", node.Failed},
		{"", node.Failed},
	}
	for _, c := range cases {
		if got := parseUDP(c.out); got.Outcome != c.want {
			t.Errorf("parseUDP(%q) = %s, want %s", c.out, got.Outcome, c.want)
		}
	}
}

func TestParsePMTU(t *testing.T) {
	p, err := parsePMTU("pmtu=1400\nhow=search\n")
	if err != nil || p != (node.PMTU{Bytes: 1400, Method: node.PMTUProbed}) {
		t.Fatalf("got %+v %v", p, err)
	}
	if _, err := parsePMTU("err=even a minimal DF ping gets no reply\n"); err == nil {
		t.Fatal("want error")
	}
}

func TestParseRoute(t *testing.T) {
	r := parseRoute("10.9.0.2 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0", "9001")
	if r != (node.Route{Dev: "eth0", Src: "10.0.0.5", Via: "10.0.0.1", MTU: 9001}) {
		t.Fatalf("got %+v", r)
	}
	if s := r.String(); s != "dev eth0 src 10.0.0.5 via 10.0.0.1, mtu 9001" {
		t.Fatalf("String() = %q", s)
	}
}

func TestParseFacts(t *testing.T) {
	f, tools := parseFacts("hostname=db1\narch=aarch64\ntool=ping\ntool=ip\naddr=10.0.0.5 eth0\naddr=fd00::5 eth1\n")
	if f.Hostname != "db1" || f.Arch != "aarch64" || !tools["ping"] || !tools["ip"] || tools["nc"] {
		t.Fatalf("got %+v %v", f, tools)
	}
	if len(f.Capabilities) != 2 || f.Capabilities[0] != "ip" {
		t.Fatalf("capabilities %v", f.Capabilities)
	}
	if len(f.Addrs) != 2 || f.Addrs[1] != (node.Addr{IP: "fd00::5", Dev: "eth1"}) {
		t.Fatalf("addrs %+v", f.Addrs)
	}
}

func TestParseIperf(t *testing.T) {
	bps, err := parseIperf(`{"start":{},"end":{"sum_received":{"bits_per_second":9.41e9}}}`)
	if err != nil || bps != 9.41e9 {
		t.Fatalf("got %v %v", bps, err)
	}
	if _, err := parseIperf(`{"error":"unable to connect to server: Connection refused"}`); err == nil {
		t.Fatal("want error")
	}
}
