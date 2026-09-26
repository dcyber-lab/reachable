// Package node is the contract between the diagnosis logic and the
// machines it runs on.
//
// A Node is one machine seen through whatever reaches it: shell scripts over
// ssh, a native agent, a service that dispatches work and collects reports.
// The diagnosis in package probe only ever talks to this interface, so a new
// way of reaching machines is a new Node (or, for anything that can run a
// bash script and hand back its stdout, just a new shell.Runner).
package node

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors a Node returns so the caller can tell "can't check" from "checked,
// and it's broken". Wrap them with the reason: fmt.Errorf("%w: no ping", ErrUnsupported).
var (
	// ErrUnsupported: this node can't do that here (tool missing, no permission).
	ErrUnsupported = errors.New("unsupported")
	// ErrInUse: something already listens on that port.
	ErrInUse = errors.New("port in use")
	// ErrNoRoute: the node has no route to the address.
	ErrNoRoute = errors.New("no route")
)

// Addr is an address configured on one of a node's interfaces.
type Addr struct {
	IP  string `json:"ip"`
	Dev string `json:"dev"`
}

// Facts describe a node, gathered once up front.
type Facts struct {
	Hostname string `json:"hostname"`
	Arch     string `json:"arch,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	User     string `json:"user,omitempty"`
	Addrs    []Addr `json:"addrs"`
	// Capabilities is informational only: what this node's implementation
	// found to work with (for the shell node, the tools on PATH).
	Capabilities []string `json:"capabilities,omitempty"`
}

// Route is how a node would send packets to an address.
type Route struct {
	Dev string `json:"dev"`
	Src string `json:"src,omitempty"`
	Via string `json:"via,omitempty"`
	MTU int    `json:"mtu,omitempty"`
}

func (r Route) String() string {
	s := "dev " + r.Dev
	if r.Src != "" {
		s += " src " + r.Src
	}
	if r.Via != "" {
		s += " via " + r.Via
	} else {
		s += " (directly connected)"
	}
	if r.MTU > 0 {
		s += fmt.Sprintf(", mtu %d", r.MTU)
	}
	return s
}

// Ping is the summary of an ICMP echo run.
type Ping struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	AvgMS    float64 `json:"avg_ms"`
}

// Proto is a transport protocol.
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// Outcome is how a dial ended.
type Outcome string

const (
	// Open: TCP connected; UDP got an answer to its probe.
	Open Outcome = "open"
	// Timeout: nothing came back in time.
	Timeout Outcome = "timeout"
	// Refused: TCP RST, or ICMP port-unreachable for UDP.
	Refused Outcome = "refused"
	// Unreachable: no route / host or network unreachable.
	Unreachable Outcome = "unreachable"
	// Failed: anything else; Dial.Msg says what.
	Failed Outcome = "failed"
)

// Dial is the result of one connection attempt.
type Dial struct {
	Outcome Outcome
	Elapsed time.Duration
	Msg     string
}

// Listener is a temporary listener that waits for one probe.
type Listener interface {
	// Via names what listens (e.g. "python3"), for the report.
	Via() string
	// Peer waits up to timeout for the probe. arrived reports whether it
	// came at all; addr is the source address it came from, "" if the
	// implementation can't tell.
	Peer(timeout time.Duration) (addr string, arrived bool)
	Close()
}

// PMTUMethod says how a path MTU was found, which is itself a diagnosis.
type PMTUMethod string

const (
	// PMTUInterface: a packet of the full interface MTU got through.
	PMTUInterface PMTUMethod = "interface"
	// PMTUReported: a hop answered "fragmentation needed" (PMTUD works).
	PMTUReported PMTUMethod = "reported"
	// PMTUProbed: bigger packets vanished silently; found by bisecting.
	PMTUProbed PMTUMethod = "probed"
)

// PMTU is the largest packet (IP header included) that crosses a path.
type PMTU struct {
	Bytes  int
	Method PMTUMethod
}

// Node is one machine.
type Node interface {
	Facts(ctx context.Context) (Facts, error)
	// Resolve looks name up the way programs on this node would.
	Resolve(ctx context.Context, name string) ([]string, error)
	Route(ctx context.Context, ip string) (Route, error)
	Ping(ctx context.Context, ip string, count int) (Ping, error)
	// Dial connects to ip:port. For UDP it sends a probe datagram and
	// waits for a Listener's answer.
	Dial(ctx context.Context, proto Proto, ip string, port int, timeout time.Duration) (Dial, error)
	// Listen starts a temporary listener on port that lives at most d.
	// dialed is the address the peer will dial, so the listener can pick
	// the right address family. Returns ErrInUse if the port is taken.
	Listen(ctx context.Context, proto Proto, port int, dialed string, d time.Duration) (Listener, error)
	PMTU(ctx context.Context, ip string) (PMTU, error)
	// Trace returns the hops towards ip, human-readable, one per line.
	Trace(ctx context.Context, ip string) ([]string, error)
	// ServeBandwidth starts a one-shot bandwidth test server on port.
	ServeBandwidth(ctx context.Context, port int, d time.Duration) (Stopper, error)
	// MeasureBandwidth sends to a ServeBandwidth server for d and
	// returns the bits per second that arrived.
	MeasureBandwidth(ctx context.Context, ip string, port int, d time.Duration) (float64, error)
	Close() error
}

// Stopper is something running that can be stopped.
type Stopper interface{ Close() }

// Backend opens Nodes for one kind of target.
type Backend interface {
	// Open reaches target (the part after "scheme://") and returns the
	// node and the address other nodes should dial to reach it, or "" if
	// the backend has no idea.
	Open(ctx context.Context, target string) (n Node, addr string, err error)
}

// Registry maps target schemes to backends.
type Registry map[string]Backend

// DefaultScheme is used for targets written without a scheme.
const DefaultScheme = "ssh"

// Open parses spec as "scheme://target" (a bare target means ssh) and opens it.
func (r Registry) Open(ctx context.Context, spec string) (Node, string, error) {
	scheme, target, ok := strings.Cut(spec, "://")
	if !ok {
		scheme, target = DefaultScheme, spec
	}
	b, ok := r[scheme]
	if !ok {
		return nil, "", fmt.Errorf("%s: unknown backend %q (have: %s)", spec, scheme, strings.Join(r.Schemes(), ", "))
	}
	return b.Open(ctx, target)
}

// Schemes lists the registered schemes, sorted.
func (r Registry) Schemes() []string {
	var s []string
	for k := range r {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}
