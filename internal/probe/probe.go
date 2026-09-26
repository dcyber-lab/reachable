// Package probe decides whether one node can reach another, and if not,
// what is in the way. It only talks to node.Node, so it doesn't know or care
// how commands reach the machines.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
)

// Status of one check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
	Info Status = "info"
)

// Check is one finding. Code is stable and meant for programs; Detail is
// prose for people and may change.
type Check struct {
	Name   string   `json:"name"`
	Status Status   `json:"status"`
	Code   string   `json:"code"`
	Detail string   `json:"detail"`
	Lines  []string `json:"lines,omitempty"`
}

// Side is one of the two nodes.
type Side struct {
	Label  string     `json:"label"`  // "A" or "B"
	Target string     `json:"target"` // as given, e.g. "web1" or "local://"
	Addr   string     `json:"addr"`   // what the other side dials
	Facts  node.Facts `json:"facts"`
	Node   node.Node  `json:"-"`
}

// Options control which checks run.
type Options struct {
	TCPPorts       []int
	UDPPorts       []int
	PingCount      int
	ConnectTimeout time.Duration
	Trace          string // auto, always, never
	Bandwidth      bool
	IperfPort      int
	IperfTime      time.Duration
}

// Result is the one-word outcome of a direction.
type Result string

const (
	Reachable   Result = "reachable"   // every tested port open
	Partial     Result = "partial"     // some open, some blocked
	Blocked     Result = "blocked"     // host answers ping, every port blocked
	Unreachable Result = "unreachable" // nothing gets there
)

// Direction is the result of probing src -> dst.
type Direction struct {
	From    string  `json:"from"`
	To      string  `json:"to"`
	Target  string  `json:"target"`
	IP      string  `json:"ip,omitempty"`
	Checks  []Check `json:"checks"`
	Result  Result  `json:"result"`
	Verdict string  `json:"verdict"`
	OK      bool    `json:"ok"`
}

func (d *Direction) add(name, code string, st Status, format string, a ...any) *Check {
	d.Checks = append(d.Checks, Check{Name: name, Status: st, Code: code, Detail: fmt.Sprintf(format, a...)})
	return &d.Checks[len(d.Checks)-1]
}

type prober struct {
	ctx      context.Context
	src, dst *Side
	opt      Options
	d        *Direction
}

// Run probes whether src can reach dst.
func Run(ctx context.Context, src, dst *Side, opt Options) *Direction {
	p := &prober{ctx: ctx, src: src, dst: dst, opt: opt,
		d: &Direction{From: src.Label, To: dst.Label, Target: dst.Addr}}
	p.check()
	if !p.d.OK && !p.gotThrough() {
		p.hint()
	}
	return p.d
}

// unsupported records a skip when err says the node can't do this, and
// reports whether it did.
func (p *prober) unsupported(name string, on *Side, err error) bool {
	if !errors.Is(err, node.ErrUnsupported) {
		return false
	}
	why := strings.TrimPrefix(err.Error(), node.ErrUnsupported.Error()+": ")
	p.d.add(name, name+".unsupported", Skip, "can't check on %s: %s", on.Label, why)
	return true
}

func (p *prober) check() {
	d := p.d
	ip, ok := p.resolve()
	if !ok {
		d.Result, d.Verdict = Unreachable, fmt.Sprintf("UNREACHABLE: %s does not resolve %s", p.src.Label, p.dst.Addr)
		return
	}
	d.IP = ip
	p.onInterface(ip)

	route, ok := p.route(ip)
	if !ok {
		d.Result, d.Verdict = Unreachable, fmt.Sprintf("UNREACHABLE: %s has no route to %s", p.src.Label, ip)
		p.maybeTrace(ip, true)
		return
	}
	ping := p.ping(ip)
	var open, blocked []string
	for _, port := range p.opt.TCPPorts {
		if ok, known := p.port(node.TCP, ip, port, route); ok {
			open = append(open, fmt.Sprintf("tcp/%d", port))
		} else if known {
			blocked = append(blocked, fmt.Sprintf("tcp/%d", port))
		}
	}
	for _, port := range p.opt.UDPPorts {
		if ok, known := p.port(node.UDP, ip, port, route); ok {
			open = append(open, fmt.Sprintf("udp/%d", port))
		} else if known {
			blocked = append(blocked, fmt.Sprintf("udp/%d", port))
		}
	}
	pinged := ping != nil && ping.Received > 0
	if pinged {
		p.pmtu(ip, route)
	} else {
		d.add("pmtu", "pmtu.skipped", Skip, "needs ICMP to get through")
	}
	if len(blocked) == 0 {
		p.bandwidth(ip)
	} else if p.opt.Bandwidth {
		d.add("bw", "bw.skipped", Skip, "not measured while ports are blocked")
	}
	p.maybeTrace(ip, len(blocked) > 0 || ping == nil || ping.Received < ping.Sent)

	if ping != nil && !pinged && len(open) > 0 {
		for i := range d.Checks {
			if d.Checks[i].Name == "icmp" {
				d.Checks[i].Status, d.Checks[i].Code = Warn, "icmp.filtered"
				d.Checks[i].Detail = fmt.Sprintf("0/%d replies: ICMP is filtered (ports get through, so the host is up)", ping.Sent)
			}
		}
	}

	tested := len(open) + len(blocked)
	switch {
	case tested == 0 && pinged:
		d.Result, d.OK, d.Verdict = Reachable, true, "REACHABLE (ICMP only, no ports tested)"
	case tested == 0:
		d.Result, d.Verdict = Unreachable, "UNREACHABLE: no ping reply and no ports tested"
	case len(blocked) == 0:
		d.Result, d.OK, d.Verdict = Reachable, true, "REACHABLE on "+strings.Join(open, ",")
	case len(open) > 0:
		d.Result = Partial
		d.Verdict = fmt.Sprintf("PARTIAL: %s open, %s blocked", strings.Join(open, ","), strings.Join(blocked, ","))
	case pinged:
		d.Result, d.Verdict = Blocked, "BLOCKED: host answers ping but every tested port is blocked"
	default:
		d.Result, d.Verdict = Unreachable, "UNREACHABLE: no ping reply and every tested port is blocked"
	}
}

// gotThrough reports whether anything at all reached dst at this address.
func (p *prober) gotThrough() bool {
	for _, c := range p.d.Checks {
		probe := c.Name == "icmp" || strings.HasPrefix(c.Name, "tcp/") || strings.HasPrefix(c.Name, "udp/")
		if probe && c.Status == OK {
			return true
		}
	}
	return false
}

// hint points at dst's other addresses: by default we dial what the backend
// says (for ssh the HostName from ssh -G), which is often a public or
// management address rather than the one the two machines use between them.
func (p *prober) hint() {
	var other []string
	for _, a := range p.dst.Facts.Addrs {
		if a.IP != p.d.IP && a.IP != p.dst.Addr {
			other = append(other, a.IP+" ("+a.Dev+")")
		}
	}
	if len(other) == 0 {
		return
	}
	p.d.add("hint", "hint.other_addrs", Info, "%s also has %s; to dial another one pass -%s-addr",
		p.dst.Label, strings.Join(other, ", "), strings.ToLower(p.dst.Label))
}

// resolve turns dst.Addr into the IP src will dial.
func (p *prober) resolve() (string, bool) {
	name := p.dst.Addr
	if net.ParseIP(name) != nil {
		return name, true
	}
	ips, err := p.src.Node.Resolve(p.ctx, name)
	switch {
	case p.unsupported("dns", p.src, err):
		return "", false
	case err != nil:
		p.d.add("dns", "dns.error", Fail, "%v", err)
		return "", false
	case len(ips) == 0:
		p.d.add("dns", "dns.unresolved", Fail, "%s does not resolve on %s", name, p.src.Label)
		return "", false
	}
	c := p.d.add("dns", "dns.ok", OK, "%s -> %s on %s", name, strings.Join(ips, " "), p.src.Label)
	// Split-horizon DNS is a classic reason "it works from my laptop".
	if local, err := net.LookupHost(name); err == nil && !overlaps(local, ips) {
		c.Status, c.Code = Warn, "dns.split_horizon"
		c.Detail += fmt.Sprintf("; but -> %s from here (split-horizon DNS?)", strings.Join(local, " "))
	}
	return ips[0], true
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// onInterface notes when the address dialed isn't configured on dst, which
// means NAT, a floating IP or a load balancer sits in front of it.
func (p *prober) onInterface(ip string) {
	if len(p.dst.Facts.Addrs) == 0 {
		return
	}
	var own []string
	for _, a := range p.dst.Facts.Addrs {
		if a.IP == ip {
			return
		}
		own = append(own, a.IP)
	}
	p.d.add("addr", "addr.not_local", Info, "%s is not on any interface of %s (%s): NAT, floating IP or LB in between",
		ip, p.dst.Label, strings.Join(own, " "))
}

func (p *prober) route(ip string) (node.Route, bool) {
	r, err := p.src.Node.Route(p.ctx, ip)
	switch {
	case p.unsupported("route", p.src, err):
		return node.Route{}, true
	case errors.Is(err, node.ErrNoRoute):
		p.d.add("route", "route.none", Fail, "%s", strings.TrimPrefix(err.Error(), node.ErrNoRoute.Error()+": "))
		return node.Route{}, false
	case err != nil:
		p.d.add("route", "route.error", Fail, "%v", err)
		return node.Route{}, false
	}
	p.d.add("route", "route.ok", OK, "%s", r)
	return r, true
}

func (p *prober) ping(ip string) *node.Ping {
	pg, err := p.src.Node.Ping(p.ctx, ip, p.opt.PingCount)
	switch {
	case p.unsupported("icmp", p.src, err):
		return nil
	case err != nil:
		p.d.add("icmp", "icmp.error", Fail, "%v", err)
		return nil
	case pg.Received == pg.Sent:
		p.d.add("icmp", "icmp.ok", OK, "%d/%d replies, avg %.2f ms", pg.Received, pg.Sent, pg.AvgMS)
	case pg.Received > 0:
		p.d.add("icmp", "icmp.loss", Warn, "%d/%d replies (%.0f%% loss), avg %.2f ms",
			pg.Received, pg.Sent, 100*float64(pg.Sent-pg.Received)/float64(pg.Sent), pg.AvgMS)
	default:
		p.d.add("icmp", "icmp.no_reply", Fail, "0/%d replies: ICMP filtered or host down", pg.Sent)
	}
	return &pg
}

// port checks one TCP or UDP port. When nothing listens there on dst it
// starts a throwaway listener first, so "open" means the probe really
// reached dst, and the listener can say which source address it saw.
// known is false when the check couldn't tell either way.
func (p *prober) port(proto node.Proto, ip string, port int, route node.Route) (open, known bool) {
	name := fmt.Sprintf("%s/%d", proto, port)
	code := func(s string) string { return string(proto) + "." + s }
	timeout := p.opt.ConnectTimeout

	mode, why := "listener", ""
	lst, err := p.dst.Node.Listen(p.ctx, proto, port, ip, timeout+5*time.Second)
	switch {
	case err == nil:
		defer lst.Close()
	case errors.Is(err, node.ErrInUse):
		mode = "service"
	default:
		mode, why = "none", strings.TrimPrefix(err.Error(), node.ErrUnsupported.Error()+": ")
	}

	if proto == node.UDP && mode != "listener" {
		// No handshake: without our own listener nothing would tell us.
		if mode == "service" {
			p.d.add(name, code("in_use"), Skip, "something already holds %s on %s; UDP has no handshake, "+
				"so without our own listener there is nothing to check against", name, p.dst.Label)
		} else {
			p.d.add(name, code("unsupported"), Skip, "no listener on %s: %s", p.dst.Label, why)
		}
		return false, false
	}

	res, err := p.src.Node.Dial(p.ctx, proto, ip, port, timeout)
	if p.unsupported(name, p.src, err) {
		return false, false
	}
	if err != nil {
		p.d.add(name, code("error"), Fail, "%v", err)
		return false, true
	}
	peer, arrived := "", false
	if mode == "listener" {
		wait := 3 * time.Second
		if res.Outcome != node.Open {
			wait = 500 * time.Millisecond // a UDP probe may still have landed
		}
		peer, arrived = lst.Peer(wait)
	}
	snat := arrived && peer != "" && route.Src != "" && peer != route.Src
	ms := res.Elapsed.Milliseconds()

	if proto == node.UDP {
		switch {
		case arrived && res.Outcome == node.Open && snat:
			p.d.add(name, code("snat"), OK, "datagram reached %s and the reply came back; %s sees %s as %s, not %s (SNAT in between)",
				p.dst.Label, p.dst.Label, p.src.Label, peer, route.Src)
		case arrived && res.Outcome == node.Open:
			p.d.add(name, code("open"), OK, "datagram reached %s and the reply came back", p.dst.Label)
		case arrived:
			p.d.add(name, code("reply_filtered"), Warn, "datagram reached %s, but its reply never got back to %s: "+
				"return path filtered (stateful firewall without UDP tracking, asymmetric route?)", p.dst.Label, p.src.Label)
		case res.Outcome == node.Refused:
			p.d.add(name, code("rejected"), Fail, "ICMP port-unreachable while %s was listening: a REJECT rule in between", p.dst.Label)
			return false, true
		case res.Outcome == node.Open:
			p.d.add(name, code("intercepted"), Warn, "got a reply, but %s's listener never saw the datagram: "+
				"something in between answered for %s", p.dst.Label, p.dst.Label)
			return false, true
		case res.Outcome == node.Timeout:
			p.d.add(name, code("dropped"), Fail, "datagrams never reached %s within %s: dropped (firewall / security group / ACL)",
				p.dst.Label, timeout)
			return false, true
		default:
			p.d.add(name, code("error"), Fail, "send failed: %s", res.Msg)
			return false, true
		}
		return true, true
	}

	switch res.Outcome {
	case node.Open:
		switch {
		case mode == "service":
			p.d.add(name, code("open"), OK, "open in %d ms (existing service on %s)", ms, p.dst.Label)
		case mode == "none":
			p.d.add(name, code("open"), OK, "open in %d ms", ms)
		case !arrived:
			p.d.add(name, code("intercepted"), Warn, "connected in %d ms, but %s's listener never saw it: something in between "+
				"answered for %s (proxy, DNAT to another host?)", ms, p.dst.Label, p.dst.Label)
			return false, true
		case snat:
			p.d.add(name, code("snat"), OK, "open in %d ms; %s sees %s as %s, not %s (SNAT in between)",
				ms, p.dst.Label, p.src.Label, peer, route.Src)
		default:
			p.d.add(name, code("open"), OK, "open in %d ms (temporary listener on %s got the connection)", ms, p.dst.Label)
		}
		return true, true
	case node.Timeout:
		p.d.add(name, code("dropped"), Fail, "timed out after %s: packets dropped (firewall / security group / ACL)", timeout)
	case node.Refused:
		switch mode {
		case "listener":
			p.d.add(name, code("rejected"), Fail, "refused while %s was listening: a REJECT rule in between", p.dst.Label)
		case "service":
			p.d.add(name, code("refused"), Fail, "refused although something listens on %s:%d: bound to another address, or a REJECT rule",
				p.dst.Label, port)
		default:
			p.d.add(name, code("refused_no_listener"), Warn, "refused: nothing listens and no temporary listener (%s); "+
				"%s's kernel (or a REJECT rule) answered, so packets do get there", why, p.dst.Label)
		}
	case node.Unreachable:
		p.d.add(name, code("unreachable"), Fail, "%s", res.Msg)
	default:
		p.d.add(name, code("error"), Fail, "connect failed: %s", res.Msg)
	}
	return false, true
}

func (p *prober) pmtu(ip string, route node.Route) {
	m, err := p.src.Node.PMTU(p.ctx, ip)
	switch {
	case p.unsupported("pmtu", p.src, err):
		return
	case err != nil:
		p.d.add("pmtu", "pmtu.error", Warn, "%v", err)
	case m.Method == node.PMTUReported:
		p.d.add("pmtu", "pmtu.reported", OK, "%d; smaller than %s's MTU %d, but a hop says so via ICMP frag-needed, so PMTUD works",
			m.Bytes, route.Dev, route.MTU)
	case m.Method == node.PMTUProbed:
		p.d.add("pmtu", "pmtu.blackhole", Warn, "%d; bigger packets vanish without ICMP frag-needed: PMTU black hole, "+
			"large transfers may hang (lower the MTU or clamp TCP MSS)", m.Bytes)
	default:
		p.d.add("pmtu", "pmtu.ok", OK, "%d", m.Bytes)
	}
}

func (p *prober) bandwidth(ip string) {
	if !p.opt.Bandwidth {
		return
	}
	srv, err := p.dst.Node.ServeBandwidth(p.ctx, p.opt.IperfPort, p.opt.IperfTime+20*time.Second)
	switch {
	case p.unsupported("bw", p.dst, err):
		return
	case err != nil:
		p.d.add("bw", "bw.error", Fail, "%v", err)
		return
	}
	defer srv.Close()
	bps, err := p.src.Node.MeasureBandwidth(p.ctx, ip, p.opt.IperfPort, p.opt.IperfTime)
	switch {
	case p.unsupported("bw", p.src, err):
	case err != nil:
		p.d.add("bw", "bw.error", Fail, "tcp/%d: %v", p.opt.IperfPort, err)
	default:
		p.d.add("bw", "bw.ok", OK, "%s (%s TCP, %s -> %s)", humanBits(bps), p.opt.IperfTime, p.src.Label, p.dst.Label)
	}
}

func (p *prober) maybeTrace(ip string, trouble bool) {
	if p.opt.Trace == "never" || (p.opt.Trace == "auto" && !trouble) {
		return
	}
	lines, err := p.src.Node.Trace(p.ctx, ip)
	switch {
	case p.unsupported("trace", p.src, err):
	case err != nil:
		p.d.add("trace", "trace.error", Info, "%v", err)
	case len(lines) == 0:
		p.d.add("trace", "trace.silent", Info, "%s -> %s: no hops answered", p.src.Label, ip)
	default:
		p.d.add("trace", "trace.hops", Info, "%s -> %s", p.src.Label, ip).Lines = lines
	}
}

func humanBits(bps float64) string {
	units := []string{"bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"}
	i := 0
	for bps >= 1000 && i < len(units)-1 {
		bps /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", bps, units[i])
}
