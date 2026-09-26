// Package probe decides whether one server can reach another by running
// small bash scripts on both over ssh.
package probe

import (
	"context"
	"embed"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dcyber-lab/reachable/internal/remote"
)

//go:embed scripts/*.sh
var scripts embed.FS

func script(name string) string {
	b, err := scripts.ReadFile("scripts/" + name + ".sh")
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Status of one check.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
	Info Status = "info"
)

// Check is one line of the report.
type Check struct {
	Name   string   `json:"name"`
	Status Status   `json:"status"`
	Detail string   `json:"detail"`
	Lines  []string `json:"lines,omitempty"`
}

// Addr is an address configured on one of a host's interfaces.
type Addr struct {
	IP  string `json:"ip"`
	Dev string `json:"dev"`
}

// Facts describe a host, gathered once up front.
type Facts struct {
	Hostname string          `json:"hostname"`
	Arch     string          `json:"arch"`
	Kernel   string          `json:"kernel"`
	User     string          `json:"user"`
	Tools    map[string]bool `json:"tools"`
	Addrs    []Addr          `json:"addrs"`
}

// Side is one of the two servers.
type Side struct {
	Label  string       `json:"label"`  // "A" or "B"
	Target string       `json:"target"` // what we ssh to
	Addr   string       `json:"addr"`   // what the other side dials
	Facts  Facts        `json:"facts"`
	Host   *remote.Host `json:"-"`
}

// Gather fills in s.Facts.
func (s *Side) Gather(ctx context.Context) error {
	res, err := s.Host.Run(ctx, 20*time.Second, script("facts"))
	if err != nil {
		return err
	}
	s.Facts = parseFacts(res.Stdout)
	return nil
}

func (s *Side) has(tool string) bool { return s.Facts.Tools[tool] }

// Options control which checks run.
type Options struct {
	Ports          []int // TCP
	UDPPorts       []int
	PingCount      int
	ConnectTimeout int    // seconds
	Trace          string // auto, always, never
	Bandwidth      bool
	IperfPort      int
	IperfSeconds   int
}

// Direction is the result of probing src -> dst.
type Direction struct {
	From    string  `json:"from"`
	To      string  `json:"to"`
	Target  string  `json:"target"`
	IP      string  `json:"ip,omitempty"`
	Checks  []Check `json:"checks"`
	Verdict string  `json:"verdict"`
	OK      bool    `json:"ok"`
}

func (d *Direction) add(name string, st Status, format string, a ...any) *Check {
	d.Checks = append(d.Checks, Check{Name: name, Status: st, Detail: fmt.Sprintf(format, a...)})
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
	p.run()
	return p.d
}

func (p *prober) run() {
	p.check()
	if !p.d.OK && !p.gotThrough() {
		p.hint()
	}
}

// gotThrough reports whether anything at all reached dst at this address.
func (p *prober) gotThrough() bool {
	for _, c := range p.d.Checks {
		if (c.Name == "icmp" || strings.HasPrefix(c.Name, "tcp/") || strings.HasPrefix(c.Name, "udp/")) && c.Status == OK {
			return true
		}
	}
	return false
}

// hint points at dst's other addresses: by default we dial the HostName
// from ssh -G, which is often a public or management address rather than
// the one the two servers use between themselves.
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
	p.d.add("hint", Info, "%s also has %s; to dial another one pass -%s-addr",
		p.dst.Label, strings.Join(other, ", "), strings.ToLower(p.dst.Label))
}

func (p *prober) check() {
	d := p.d
	ip, ok := p.resolve()
	if !ok {
		d.Verdict = fmt.Sprintf("UNREACHABLE: %s does not resolve %s", p.src.Label, p.dst.Addr)
		return
	}
	d.IP = ip
	p.onInterface(ip)

	route, ok := p.route(ip)
	if !ok {
		d.Verdict = fmt.Sprintf("UNREACHABLE: %s has no route to %s", p.src.Label, ip)
		p.maybeTrace(ip, true)
		return
	}
	ping := p.ping(ip)
	var open, blocked []string
	for _, port := range p.opt.Ports {
		if p.tcp(ip, port, route) {
			open = append(open, fmt.Sprintf("tcp/%d", port))
		} else {
			blocked = append(blocked, fmt.Sprintf("tcp/%d", port))
		}
	}
	for _, port := range p.opt.UDPPorts {
		if ok, known := p.udp(ip, port, route); ok {
			open = append(open, fmt.Sprintf("udp/%d", port))
		} else if known {
			blocked = append(blocked, fmt.Sprintf("udp/%d", port))
		}
	}
	if ping != nil && ping.Received > 0 {
		p.pmtu(ip, route)
	} else {
		d.add("pmtu", Skip, "needs ICMP to get through")
	}
	if len(blocked) == 0 {
		p.bandwidth(ip)
	} else if p.opt.Bandwidth {
		d.add("bw", Skip, "not measured while ports are blocked")
	}
	p.maybeTrace(ip, len(blocked) > 0 || ping == nil || ping.Received < ping.Sent)

	pinged := ping != nil && ping.Received > 0
	if ping != nil && !pinged && len(open) > 0 {
		for i := range d.Checks {
			if d.Checks[i].Name == "icmp" {
				d.Checks[i].Status = Warn
				d.Checks[i].Detail = fmt.Sprintf("0/%d replies: ICMP is filtered (ports get through, so the host is up)", ping.Sent)
			}
		}
	}
	tested := len(open) + len(blocked)
	switch {
	case tested == 0 && pinged:
		d.Verdict, d.OK = "REACHABLE (ICMP only, no ports tested)", true
	case tested == 0:
		d.Verdict = "UNREACHABLE: no ping reply and no ports tested"
	case len(blocked) == 0:
		d.Verdict, d.OK = "REACHABLE on "+strings.Join(open, ","), true
	case len(open) > 0:
		d.Verdict = fmt.Sprintf("PARTIAL: %s open, %s blocked", strings.Join(open, ","), strings.Join(blocked, ","))
	case pinged:
		d.Verdict = "BLOCKED: host answers ping but every tested port is blocked"
	default:
		d.Verdict = "UNREACHABLE: no ping reply and every tested port is blocked"
	}
}

// resolve turns dst.Addr into the IP src will dial.
func (p *prober) resolve() (string, bool) {
	name := p.dst.Addr
	if net.ParseIP(name) != nil {
		return name, true
	}
	res, err := p.src.Host.Run(p.ctx, 15*time.Second, script("resolve"), name)
	if err != nil {
		p.d.add("dns", Fail, "%v", err)
		return "", false
	}
	remoteIPs := strings.Fields(res.Stdout)
	if len(remoteIPs) == 0 {
		p.d.add("dns", Fail, "%s does not resolve on %s", name, p.src.Label)
		return "", false
	}
	c := p.d.add("dns", OK, "%s -> %s on %s", name, strings.Join(remoteIPs, " "), p.src.Label)
	// Split-horizon DNS is a classic reason "it works from my laptop".
	if local, err := net.LookupHost(name); err == nil && !overlaps(local, remoteIPs) {
		c.Status = Warn
		c.Detail += fmt.Sprintf("; but -> %s from here (split-horizon DNS?)", strings.Join(local, " "))
	}
	return remoteIPs[0], true
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
	for _, a := range p.dst.Facts.Addrs {
		if a.IP == ip {
			return
		}
	}
	var own []string
	for _, a := range p.dst.Facts.Addrs {
		own = append(own, a.IP)
	}
	p.d.add("addr", Info, "%s is not on any interface of %s (%s): NAT, floating IP or LB in between",
		ip, p.dst.Label, strings.Join(own, " "))
}

func (p *prober) route(ip string) (Route, bool) {
	if !p.src.has("ip") {
		p.d.add("route", Skip, "no ip(8) on %s", p.src.Label)
		return Route{}, true
	}
	res, err := p.src.Host.Run(p.ctx, 15*time.Second, script("route"), ip)
	if err != nil {
		p.d.add("route", Fail, "%v", err)
		return Route{}, false
	}
	m := kv(res.Stdout)
	if e := first(m, "err"); e != "" {
		p.d.add("route", Fail, "%s", e)
		return Route{}, false
	}
	r := parseRoute(first(m, "route"), first(m, "mtu"))
	p.d.add("route", OK, "%s", r)
	return r, true
}

func (p *prober) ping(ip string) *Ping {
	if !p.src.has("ping") {
		p.d.add("icmp", Skip, "no ping on %s", p.src.Label)
		return nil
	}
	timeout := time.Duration(p.opt.PingCount)*time.Second + 10*time.Second
	res, err := p.src.Host.Run(p.ctx, timeout, script("ping"), ip, strconv.Itoa(p.opt.PingCount))
	if err != nil {
		p.d.add("icmp", Fail, "%v", err)
		return nil
	}
	pg, ok := parsePing(res.Stdout)
	switch {
	case !ok:
		p.d.add("icmp", Skip, "ping failed: %s", firstLine(res.Stdout))
		return nil
	case pg.Received == pg.Sent:
		p.d.add("icmp", OK, "%d/%d replies, avg %.2f ms", pg.Received, pg.Sent, pg.AvgMS)
	case pg.Received > 0:
		p.d.add("icmp", Warn, "%d/%d replies (%.0f%% loss), avg %.2f ms",
			pg.Received, pg.Sent, 100*float64(pg.Sent-pg.Received)/float64(pg.Sent), pg.AvgMS)
	default:
		p.d.add("icmp", Fail, "0/%d replies: ICMP filtered or host down", pg.Sent)
	}
	return &pg
}

// tcp checks one port. When nothing listens on dst it starts a throwaway
// listener there first, so "open" means the SYN really reached dst, and the
// listener can report which source address it saw.
func (p *prober) tcp(ip string, port int, route Route) bool {
	name := fmt.Sprintf("tcp/%d", port)
	secs := p.opt.ConnectTimeout

	lst, mode, why := p.listen("tcp", ip, port, secs+5)
	if lst != nil {
		defer lst.Stop()
	}

	res, err := p.src.Host.Run(p.ctx, time.Duration(secs+15)*time.Second, script("connect"),
		ip, strconv.Itoa(port), strconv.Itoa(secs))
	if err != nil {
		p.d.add(name, Fail, "%v", err)
		return false
	}
	conn, ms, msg := classifyConnect(res.Stdout)

	switch conn {
	case ConnOpen:
		switch mode {
		case "service":
			p.d.add(name, OK, "open in %d ms (existing service on %s)", ms, p.dst.Label)
		case "listener":
			peer := waitPeer(lst, 3*time.Second)
			switch {
			case peer == "":
				p.d.add(name, Warn, "connected in %d ms, but %s's listener never saw it: something in between "+
					"answered for %s (proxy, DNAT to another host?)", ms, p.dst.Label, p.dst.Label)
				return false
			case peer == "?" || route.Src == "" || peer == route.Src:
				p.d.add(name, OK, "open in %d ms (temporary listener on %s got the connection)", ms, p.dst.Label)
			default:
				p.d.add(name, OK, "open in %d ms; %s sees %s as %s, not %s (SNAT in between)",
					ms, p.dst.Label, p.src.Label, peer, route.Src)
			}
		default:
			p.d.add(name, OK, "open in %d ms", ms)
		}
		return true

	case ConnTimeout:
		p.d.add(name, Fail, "timed out after %ds: packets dropped (firewall / security group / ACL)", secs)
	case ConnRefused:
		switch mode {
		case "listener":
			p.d.add(name, Fail, "refused while %s was listening: a REJECT rule in between", p.dst.Label)
		case "service":
			p.d.add(name, Fail, "refused although something listens on %s:%d: bound to another address, or a REJECT rule",
				p.dst.Label, port)
		default:
			p.d.add(name, Warn, "refused: nothing listens and no temporary listener (%s); "+
				"%s's kernel (or a REJECT rule) answered, so packets do get there", why, p.dst.Label)
		}
	case ConnNoRoute:
		p.d.add(name, Fail, "%s", msg)
	default:
		p.d.add(name, Fail, "connect failed: %s", msg)
	}
	return false
}

// listen starts listen.sh on dst. mode is "listener" when our own listener
// is up, "service" when something already holds the port, and "none" (with
// why) when neither; lst is nil only when ssh itself failed.
func (p *prober) listen(proto, ip string, port, secs int) (lst *remote.Proc, mode, why string) {
	fam := "4"
	if strings.Contains(ip, ":") {
		fam = "6"
	}
	lst, err := p.dst.Host.Start(p.ctx, script("listen"), proto, strconv.Itoa(port), strconv.Itoa(secs), fam)
	if err != nil {
		return nil, "none", err.Error()
	}
	for {
		line, ok := lst.Next(15 * time.Second)
		switch {
		case !ok:
			return lst, "none", "listener did not start"
		case line == "INUSE":
			return lst, "service", ""
		case strings.HasPrefix(line, "READY"):
			return lst, "listener", ""
		case strings.HasPrefix(line, "ERR "):
			return lst, "none", strings.TrimPrefix(line, "ERR ")
		}
	}
}

// waitPeer returns the address the listener saw the probe come from, "?"
// if it got one but can't tell, or "" if nothing arrived.
func waitPeer(lst *remote.Proc, timeout time.Duration) string {
	for {
		line, ok := lst.Next(timeout)
		switch {
		case !ok, line == "NOCONN":
			return ""
		case strings.HasPrefix(line, "PEER "):
			return strings.TrimPrefix(line, "PEER ")
		}
	}
}

// udp checks one port. UDP has no handshake, so the only proof a datagram
// arrived is our own listener on dst receiving it; its reply then tests the
// way back. Returns open, and known=false when it could not tell.
func (p *prober) udp(ip string, port int, route Route) (open, known bool) {
	name := fmt.Sprintf("udp/%d", port)
	secs := p.opt.ConnectTimeout
	lst, mode, why := p.listen("udp", ip, port, secs+5)
	if lst != nil {
		defer lst.Stop()
	}
	switch mode {
	case "service":
		p.d.add(name, Skip, "something already holds udp/%d on %s; UDP has no handshake, "+
			"so without our own listener there is nothing to check against", port, p.dst.Label)
		return false, false
	case "none":
		p.d.add(name, Skip, "no listener on %s: %s", p.dst.Label, why)
		return false, false
	}

	res, err := p.src.Host.Run(p.ctx, time.Duration(secs+15)*time.Second, script("udp"),
		ip, strconv.Itoa(port), strconv.Itoa(secs))
	if err != nil {
		p.d.add(name, Fail, "%v", err)
		return false, true
	}
	m := kv(res.Stdout)
	reply, sendErr := first(m, "reply"), first(m, "err")
	peer := waitPeer(lst, 2*time.Second)

	switch {
	case peer != "" && reply == "pong":
		detail := fmt.Sprintf("datagram reached %s and the reply came back", p.dst.Label)
		if peer != "?" && route.Src != "" && peer != route.Src {
			detail += fmt.Sprintf("; %s sees %s as %s, not %s (SNAT in between)", p.dst.Label, p.src.Label, peer, route.Src)
		}
		p.d.add(name, OK, "%s", detail)
	case peer != "":
		p.d.add(name, Warn, "datagram reached %s, but its reply never got back to %s: "+
			"return path filtered (stateful firewall without UDP tracking, asymmetric route?)", p.dst.Label, p.src.Label)
	case strings.Contains(strings.ToLower(sendErr), "refused"):
		p.d.add(name, Fail, "ICMP port-unreachable while %s was listening: a REJECT rule in between", p.dst.Label)
		return false, true
	case sendErr != "":
		p.d.add(name, Fail, "send failed: %s", sendErr)
		return false, true
	case reply == "pong":
		p.d.add(name, Warn, "got a reply, but %s's listener never saw the datagram: something in between "+
			"answered for %s", p.dst.Label, p.dst.Label)
		return false, true
	default:
		p.d.add(name, Fail, "datagrams never reached %s within %ds: dropped (firewall / security group / ACL)",
			p.dst.Label, secs)
		return false, true
	}
	return true, true
}

func (p *prober) pmtu(ip string, route Route) {
	res, err := p.src.Host.Run(p.ctx, 60*time.Second, script("pmtu"), ip)
	if err != nil {
		p.d.add("pmtu", Fail, "%v", err)
		return
	}
	m := kv(res.Stdout)
	if e := first(m, "err"); e != "" {
		p.d.add("pmtu", Warn, "%s", e)
		return
	}
	pmtu, _ := strconv.Atoi(first(m, "pmtu"))
	switch first(m, "how") {
	case "icmp":
		p.d.add("pmtu", OK, "%d; smaller than %s's MTU %d, but a hop says so via ICMP frag-needed, so PMTUD works",
			pmtu, route.Dev, route.MTU)
	case "search":
		p.d.add("pmtu", Warn, "%d; bigger packets vanish without ICMP frag-needed: PMTU black hole, "+
			"large transfers may hang (lower the MTU or clamp TCP MSS)", pmtu)
	default:
		p.d.add("pmtu", OK, "%d", pmtu)
	}
}

func (p *prober) bandwidth(ip string) {
	if !p.opt.Bandwidth {
		return
	}
	var missing []string
	for _, s := range []*Side{p.src, p.dst} {
		if !s.has("iperf3") {
			missing = append(missing, s.Label)
		}
	}
	if len(missing) > 0 {
		p.d.add("bw", Skip, "no iperf3 on %s", strings.Join(missing, ", "))
		return
	}
	port := strconv.Itoa(p.opt.IperfPort)
	srv, err := p.dst.Host.Start(p.ctx, script("iperf-server"), port, strconv.Itoa(p.opt.IperfSeconds+20))
	if err != nil {
		p.d.add("bw", Fail, "%v", err)
		return
	}
	defer srv.Stop()
	for {
		line, ok := srv.Next(10 * time.Second)
		if !ok {
			p.d.add("bw", Fail, "iperf3 server did not start on %s", p.dst.Label)
			return
		}
		if strings.HasPrefix(line, "ERR ") {
			p.d.add("bw", Fail, "%s", strings.TrimPrefix(line, "ERR "))
			return
		}
		if line == "READY" {
			break
		}
	}
	res, err := p.src.Host.Run(p.ctx, time.Duration(p.opt.IperfSeconds+20)*time.Second,
		script("iperf-client"), ip, port, strconv.Itoa(p.opt.IperfSeconds))
	if err != nil {
		p.d.add("bw", Fail, "%v", err)
		return
	}
	bps, err := parseIperf(res.Stdout)
	if err != nil {
		p.d.add("bw", Fail, "iperf3 on tcp/%s: %v", port, err)
		return
	}
	p.d.add("bw", OK, "%s (%ds TCP, %s -> %s)", humanBits(bps), p.opt.IperfSeconds, p.src.Label, p.dst.Label)
}

func (p *prober) maybeTrace(ip string, trouble bool) {
	if p.opt.Trace == "never" || (p.opt.Trace == "auto" && !trouble) {
		return
	}
	res, err := p.src.Host.Run(p.ctx, 40*time.Second, script("trace"), ip)
	if err != nil {
		p.d.add("trace", Fail, "%v", err)
		return
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		p.d.add("trace", Info, "%s -> %s: no hops answered within 15s", p.src.Label, ip)
		return
	}
	c := p.d.add("trace", Info, "%s -> %s", p.src.Label, ip)
	c.Lines = lines
}
