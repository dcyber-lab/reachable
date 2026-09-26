// Package shell implements node.Node with small bash scripts, run through
// any Runner: ssh, a local shell, or anything else that can execute a
// script and hand back its stdout.
//
// The scripts need only bash and coreutils; everything else (ip, ping,
// python3, iperf3, ...) is used when present and reported as
// node.ErrUnsupported when not.
package shell

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
)

// Runner executes bash scripts on one machine.
type Runner interface {
	// Run feeds script to `bash -s -- args...` and returns its stdout.
	// Scripts exit 0, so a non-zero exit is the Runner's own failure and
	// must come back as an error.
	Run(ctx context.Context, script string, args []string) (string, error)
	// Start is Run for long-lived scripts: it returns as soon as the
	// script is running, and streams its stdout line by line.
	Start(ctx context.Context, script string, args []string) (Stream, error)
	Close() error
}

// Stream is the stdout of a running script.
type Stream interface {
	// Next returns the next line, or ok=false on EOF or after timeout.
	Next(timeout time.Duration) (line string, ok bool)
	// Close stops the script. Every script bounds its own lifetime, so
	// nothing is left running for long even if the stop can't reach it.
	Close()
}

//go:embed scripts/*.sh
var scripts embed.FS

// script returns a script ready to run. Scripts always exit 0 and report
// through stdout, so to a Runner a non-zero exit only ever means it failed
// to run the script at all (ssh's 255, say).
func script(name string) string {
	b, err := scripts.ReadFile("scripts/" + name + ".sh")
	if err != nil {
		panic(err)
	}
	return string(b) + "exit 0\n"
}

// safeArg is what we pass as script arguments. A Runner may hand them to a
// remote login shell (bash, zsh, fish...), so nothing that needs quoting.
var safeArg = regexp.MustCompile(`^[A-Za-z0-9._:%/-]+$`)

// Node is a node.Node backed by bash scripts.
type Node struct {
	r Runner

	mu    sync.Mutex
	tools map[string]bool
}

// New returns a Node that runs its scripts through r.
func New(r Runner) *Node { return &Node{r: r} }

var _ node.Node = (*Node)(nil)

func (n *Node) run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if err := checkArgs(args); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := n.r.Run(ctx, script(name), args)
	if err != nil && ctx.Err() != nil {
		return out, fmt.Errorf("%s: timed out after %s", name, timeout)
	}
	return out, err
}

// start runs a long-lived script. Such scripts print "PID <pid>" first, so
// that Close can kill what they started instead of leaving it to run out
// its own timeout: a leftover listener would hold the port, and a rerun
// right after would find it "in use".
func (n *Node) start(ctx context.Context, name string, args ...string) (*running, error) {
	if err := checkArgs(args); err != nil {
		return nil, err
	}
	s, err := n.r.Start(ctx, script(name), args)
	if err != nil {
		return nil, err
	}
	return &running{s: s, n: n}, nil
}

type running struct {
	s   Stream
	n   *Node
	pid string
}

// Next is Stream.Next minus the PID line.
func (r *running) Next(timeout time.Duration) (string, bool) {
	for {
		line, ok := r.s.Next(timeout)
		if ok && strings.HasPrefix(line, "PID ") && r.pid == "" {
			r.pid = strings.TrimPrefix(line, "PID ")
			continue
		}
		return line, ok
	}
}

func (r *running) Close() {
	if r.pid != "" {
		_, _ = r.n.run(context.Background(), 10*time.Second, "kill", r.pid)
	}
	r.s.Close()
}

func checkArgs(args []string) error {
	for _, a := range args {
		if !safeArg.MatchString(a) {
			return fmt.Errorf("refusing unsafe script argument %q", a)
		}
	}
	return nil
}

func itoa(i int) string { return strconv.Itoa(i) }

func secs(d time.Duration) string {
	s := int(d.Round(time.Second) / time.Second)
	if s < 1 {
		s = 1
	}
	return itoa(s)
}

// need returns ErrUnsupported unless one of tools is on this node.
func (n *Node) need(ctx context.Context, tools ...string) error {
	n.mu.Lock()
	known := n.tools
	n.mu.Unlock()
	if known == nil {
		if _, err := n.Facts(ctx); err != nil {
			return err
		}
		n.mu.Lock()
		known = n.tools
		n.mu.Unlock()
	}
	for _, t := range tools {
		if known[t] {
			return nil
		}
	}
	return fmt.Errorf("%w: no %s here", node.ErrUnsupported, strings.Join(tools, " or "))
}

func (n *Node) Facts(ctx context.Context) (node.Facts, error) {
	out, err := n.run(ctx, 20*time.Second, "facts")
	if err != nil {
		return node.Facts{}, err
	}
	f, tools := parseFacts(out)
	n.mu.Lock()
	n.tools = tools
	n.mu.Unlock()
	return f, nil
}

func (n *Node) Resolve(ctx context.Context, name string) ([]string, error) {
	if err := n.need(ctx, "getent"); err != nil {
		return nil, err
	}
	out, err := n.run(ctx, 15*time.Second, "resolve", name)
	return strings.Fields(out), err
}

func (n *Node) Route(ctx context.Context, ip string) (node.Route, error) {
	if err := n.need(ctx, "ip"); err != nil {
		return node.Route{}, err
	}
	out, err := n.run(ctx, 15*time.Second, "route", ip)
	if err != nil {
		return node.Route{}, err
	}
	m := kv(out)
	if e := first(m, "err"); e != "" {
		return node.Route{}, fmt.Errorf("%w: %s", node.ErrNoRoute, e)
	}
	return parseRoute(first(m, "route"), first(m, "mtu")), nil
}

func (n *Node) Ping(ctx context.Context, ip string, count int) (node.Ping, error) {
	if err := n.need(ctx, "ping"); err != nil {
		return node.Ping{}, err
	}
	out, err := n.run(ctx, time.Duration(count)*time.Second+10*time.Second, "ping", ip, itoa(count))
	if err != nil {
		return node.Ping{}, err
	}
	p, ok := parsePing(out)
	if !ok {
		return p, fmt.Errorf("%w: %s", node.ErrUnsupported, firstLine(out))
	}
	return p, nil
}

func (n *Node) Dial(ctx context.Context, proto node.Proto, ip string, port int, timeout time.Duration) (node.Dial, error) {
	if err := n.need(ctx, "timeout"); err != nil {
		return node.Dial{}, err
	}
	name, parse := "connect", parseConnect
	if proto == node.UDP {
		name, parse = "udp", parseUDP
	}
	out, err := n.run(ctx, timeout+15*time.Second, name, ip, itoa(port), secs(timeout))
	if err != nil {
		return node.Dial{}, err
	}
	return parse(out), nil
}

func (n *Node) Listen(ctx context.Context, proto node.Proto, port int, dialed string, d time.Duration) (node.Listener, error) {
	fam := "4"
	if strings.Contains(dialed, ":") {
		fam = "6"
	}
	s, err := n.start(ctx, "listen", string(proto), itoa(port), secs(d), fam)
	if err != nil {
		return nil, err
	}
	for {
		line, ok := s.Next(15 * time.Second)
		switch {
		case !ok:
			s.Close()
			return nil, errors.New("listener did not start")
		case line == "INUSE":
			s.Close()
			return nil, node.ErrInUse
		case strings.HasPrefix(line, "ERR "):
			s.Close()
			return nil, fmt.Errorf("%w: %s", node.ErrUnsupported, strings.TrimPrefix(line, "ERR "))
		case strings.HasPrefix(line, "READY "):
			return &listener{r: s, via: strings.TrimPrefix(line, "READY ")}, nil
		}
	}
}

type listener struct {
	r   *running
	via string
}

func (l *listener) Via() string { return l.via }
func (l *listener) Close()      { l.r.Close() }

func (l *listener) Peer(timeout time.Duration) (string, bool) {
	for {
		line, ok := l.r.Next(timeout)
		switch {
		case !ok, line == "NOCONN":
			return "", false
		case line == "PEER ?":
			return "", true
		case strings.HasPrefix(line, "PEER "):
			return strings.TrimPrefix(line, "PEER "), true
		}
	}
}

func (n *Node) PMTU(ctx context.Context, ip string) (node.PMTU, error) {
	if err := n.need(ctx, "ping"); err != nil {
		return node.PMTU{}, err
	}
	out, err := n.run(ctx, 60*time.Second, "pmtu", ip)
	if err != nil {
		return node.PMTU{}, err
	}
	return parsePMTU(out)
}

func (n *Node) Trace(ctx context.Context, ip string) ([]string, error) {
	if err := n.need(ctx, "tracepath", "traceroute"); err != nil {
		return nil, err
	}
	out, err := n.run(ctx, 40*time.Second, "trace", ip)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

func (n *Node) ServeBandwidth(ctx context.Context, port int, d time.Duration) (node.Stopper, error) {
	if err := n.need(ctx, "iperf3"); err != nil {
		return nil, err
	}
	s, err := n.start(ctx, "iperf-server", itoa(port), secs(d))
	if err != nil {
		return nil, err
	}
	for {
		line, ok := s.Next(10 * time.Second)
		switch {
		case !ok:
			s.Close()
			return nil, errors.New("iperf3 server did not start")
		case strings.HasPrefix(line, "ERR "):
			s.Close()
			return nil, errors.New(strings.TrimPrefix(line, "ERR "))
		case line == "READY":
			return s, nil
		}
	}
}

func (n *Node) MeasureBandwidth(ctx context.Context, ip string, port int, d time.Duration) (float64, error) {
	if err := n.need(ctx, "iperf3"); err != nil {
		return 0, err
	}
	out, err := n.run(ctx, d+20*time.Second, "iperf-client", ip, itoa(port), secs(d))
	if err != nil {
		return 0, err
	}
	return parseIperf(out)
}

func (n *Node) Close() error { return n.r.Close() }
