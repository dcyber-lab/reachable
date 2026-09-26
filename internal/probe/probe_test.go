package probe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
)

// fake is a scripted node.Node: each field is what the matching method
// returns. The zero value is a healthy node with nothing on it.
type fake struct {
	route     node.Route
	routeErr  error
	ping      node.Ping
	pingErr   error
	dial      map[string]node.Dial // "tcp/80" -> result
	listenErr map[string]error     // "tcp/80" -> error from Listen
	peer      map[string]string    // "tcp/80" -> source addr the listener sees; absent = nothing arrives
	pmtu      node.PMTU
}

func (f *fake) Facts(context.Context) (node.Facts, error) { return node.Facts{}, nil }
func (f *fake) Resolve(context.Context, string) ([]string, error) {
	return nil, fmt.Errorf("%w: no resolver", node.ErrUnsupported)
}
func (f *fake) Route(context.Context, string) (node.Route, error) { return f.route, f.routeErr }
func (f *fake) Ping(context.Context, string, int) (node.Ping, error) {
	return f.ping, f.pingErr
}
func (f *fake) Dial(_ context.Context, proto node.Proto, _ string, port int, _ time.Duration) (node.Dial, error) {
	return f.dial[fmt.Sprintf("%s/%d", proto, port)], nil
}
func (f *fake) Listen(_ context.Context, proto node.Proto, port int, _ string, _ time.Duration) (node.Listener, error) {
	k := fmt.Sprintf("%s/%d", proto, port)
	if err := f.listenErr[k]; err != nil {
		return nil, err
	}
	addr, ok := f.peer[k]
	return fakeListener{addr, ok}, nil
}
func (f *fake) PMTU(context.Context, string) (node.PMTU, error) { return f.pmtu, nil }
func (f *fake) Trace(context.Context, string) ([]string, error) { return nil, nil }
func (f *fake) ServeBandwidth(context.Context, int, time.Duration) (node.Stopper, error) {
	return nil, fmt.Errorf("%w: no iperf3", node.ErrUnsupported)
}
func (f *fake) MeasureBandwidth(context.Context, string, int, time.Duration) (float64, error) {
	return 0, fmt.Errorf("%w: no iperf3", node.ErrUnsupported)
}
func (f *fake) Close() error { return nil }

type fakeListener struct {
	addr    string
	arrived bool
}

func (l fakeListener) Via() string                       { return "fake" }
func (l fakeListener) Peer(time.Duration) (string, bool) { return l.addr, l.arrived }
func (l fakeListener) Close()                            {}

func run(t *testing.T, src, dst *fake, opt Options) *Direction {
	t.Helper()
	if opt.PingCount == 0 {
		opt.PingCount = 3
	}
	opt.ConnectTimeout = time.Second
	opt.Trace = "never"
	a := &Side{Label: "A", Node: src}
	b := &Side{Label: "B", Addr: "10.0.0.2", Node: dst,
		Facts: node.Facts{Addrs: []node.Addr{{IP: "10.0.0.2", Dev: "eth0"}, {IP: "192.168.9.2", Dev: "eth1"}}}}
	return Run(context.Background(), a, b, opt)
}

func codes(d *Direction) map[string]string {
	m := map[string]string{}
	for _, c := range d.Checks {
		m[c.Name] = c.Code
	}
	return m
}

var up = node.Route{Dev: "eth0", Src: "10.0.0.1"}
var pingOK = node.Ping{Sent: 3, Received: 3}

func TestPortDiagnosis(t *testing.T) {
	cases := []struct {
		name      string
		proto     node.Proto
		dial      node.Dial
		listenErr error
		peer      *string // nil: nothing arrives at the listener
		want      string
		open      bool
	}{
		{"tcp open", node.TCP, node.Dial{Outcome: node.Open}, nil, str("10.0.0.1"), "tcp.open", true},
		{"tcp snat", node.TCP, node.Dial{Outcome: node.Open}, nil, str("10.0.0.99"), "tcp.snat", true},
		{"tcp listener can't tell source", node.TCP, node.Dial{Outcome: node.Open}, nil, str(""), "tcp.open", true},
		{"tcp intercepted", node.TCP, node.Dial{Outcome: node.Open}, nil, nil, "tcp.intercepted", false},
		{"tcp existing service", node.TCP, node.Dial{Outcome: node.Open}, node.ErrInUse, nil, "tcp.open", true},
		{"tcp dropped", node.TCP, node.Dial{Outcome: node.Timeout}, nil, nil, "tcp.dropped", false},
		{"tcp rejected", node.TCP, node.Dial{Outcome: node.Refused}, nil, nil, "tcp.rejected", false},
		{"tcp service refuses", node.TCP, node.Dial{Outcome: node.Refused}, node.ErrInUse, nil, "tcp.refused", false},
		{"tcp no listener, refused", node.TCP, node.Dial{Outcome: node.Refused},
			fmt.Errorf("%w: Permission denied", node.ErrUnsupported), nil, "tcp.refused_no_listener", false},
		{"udp open", node.UDP, node.Dial{Outcome: node.Open}, nil, str("10.0.0.1"), "udp.open", true},
		{"udp snat", node.UDP, node.Dial{Outcome: node.Open}, nil, str("10.0.0.99"), "udp.snat", true},
		{"udp reply filtered", node.UDP, node.Dial{Outcome: node.Timeout}, nil, str("10.0.0.1"), "udp.reply_filtered", true},
		{"udp dropped", node.UDP, node.Dial{Outcome: node.Timeout}, nil, nil, "udp.dropped", false},
		{"udp rejected", node.UDP, node.Dial{Outcome: node.Refused}, nil, nil, "udp.rejected", false},
		{"udp intercepted", node.UDP, node.Dial{Outcome: node.Open}, nil, nil, "udp.intercepted", false},
		{"udp port taken", node.UDP, node.Dial{}, node.ErrInUse, nil, "udp.in_use", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := string(c.proto) + "/80"
			src := &fake{route: up, ping: pingOK, dial: map[string]node.Dial{k: c.dial}}
			dst := &fake{listenErr: map[string]error{k: c.listenErr}, peer: map[string]string{}}
			if c.peer != nil {
				dst.peer[k] = *c.peer
			}
			opt := Options{TCPPorts: []int{80}}
			if c.proto == node.UDP {
				opt = Options{UDPPorts: []int{80}}
			}
			d := run(t, src, dst, opt)
			if got := codes(d)[k]; got != c.want {
				t.Errorf("code %q, want %q; checks %+v", got, c.want, d.Checks)
			}
			if c.want != "udp.in_use" && d.OK != c.open {
				t.Errorf("ok = %v, want %v (%s)", d.OK, c.open, d.Verdict)
			}
		})
	}
}

func str(s string) *string { return &s }

func TestVerdicts(t *testing.T) {
	open := node.Dial{Outcome: node.Open}
	drop := node.Dial{Outcome: node.Timeout}
	peers := map[string]string{"tcp/1": "10.0.0.1", "tcp/2": "10.0.0.1"}

	d := run(t, &fake{route: up, ping: pingOK, dial: map[string]node.Dial{"tcp/1": open, "tcp/2": drop}},
		&fake{peer: peers}, Options{TCPPorts: []int{1, 2}})
	if d.Result != Partial || d.Verdict != "PARTIAL: tcp/1 open, tcp/2 blocked" {
		t.Errorf("partial: %s %q", d.Result, d.Verdict)
	}

	d = run(t, &fake{route: up, ping: pingOK, dial: map[string]node.Dial{"tcp/1": drop}},
		&fake{}, Options{TCPPorts: []int{1}})
	if d.Result != Blocked {
		t.Errorf("blocked: %s %q", d.Result, d.Verdict)
	}

	// ICMP filtered but a port open: the host is up, so only a warning.
	d = run(t, &fake{route: up, ping: node.Ping{Sent: 3}, dial: map[string]node.Dial{"tcp/1": open}},
		&fake{peer: peers}, Options{TCPPorts: []int{1}})
	if !d.OK || codes(d)["icmp"] != "icmp.filtered" {
		t.Errorf("icmp filtered: %v %v", d.OK, codes(d))
	}

	// Nothing gets through: hint at the other addresses B has.
	d = run(t, &fake{route: up, ping: node.Ping{Sent: 3}, dial: map[string]node.Dial{"tcp/1": drop}},
		&fake{}, Options{TCPPorts: []int{1}})
	if d.Result != Unreachable || codes(d)["hint"] != "hint.other_addrs" {
		t.Errorf("unreachable: %s %v", d.Result, codes(d))
	}

	d = run(t, &fake{routeErr: fmt.Errorf("%w: Network is unreachable", node.ErrNoRoute)},
		&fake{}, Options{TCPPorts: []int{1}})
	if d.Result != Unreachable || codes(d)["route"] != "route.none" {
		t.Errorf("no route: %s %v", d.Result, codes(d))
	}

	// A node that can't ping is a skip, not a failure.
	d = run(t, &fake{route: up, pingErr: fmt.Errorf("%w: no ping here", node.ErrUnsupported),
		dial: map[string]node.Dial{"tcp/1": open}}, &fake{peer: peers}, Options{TCPPorts: []int{1}})
	if !d.OK || codes(d)["icmp"] != "icmp.unsupported" {
		t.Errorf("no ping: %v %v", d.OK, codes(d))
	}

	d = run(t, &fake{route: up, ping: pingOK, pmtu: node.PMTU{Bytes: 1400, Method: node.PMTUProbed}},
		&fake{}, Options{})
	if codes(d)["pmtu"] != "pmtu.blackhole" {
		t.Errorf("pmtu: %v", codes(d))
	}
}
