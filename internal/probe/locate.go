package probe

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dcyber-lab/reachable/internal/node"
)

// Where a probe died, as a place on its way:
//
//	src stack -> src NIC -> network -> dst NIC (XDP here) -> dst stack -> socket
//	                     <- network <- dst NIC <- dst stack (reply)
const (
	whereSrcEgress  = "src_egress"  // on the source, before its NIC
	wherePath       = "path"        // between the two NICs
	whereDstNIC     = "dst_nic"     // on the destination's NIC or driver (ring full), before any capture
	whereDstXDP     = "dst_xdp"     // on the destination, in XDP, before any capture sees it
	whereDstIngress = "dst_ingress" // on the destination, after its NIC, before the socket
	whereDstEgress  = "dst_egress"  // the destination's reply, before its NIC
	whereReturnPath = "return_path" // the reply, between the two NICs
	whereSrcIngress = "src_ingress" // the reply, on the source after its NIC
	whereUnknown    = "unknown"
)

// How sure a finding is.
const (
	observed = "observed" // the kernel's drop trace saw our packets dropped there
	counted  = "counted"  // a drop counter there moved with our probes, and not before
	inferred = "inferred" // by elimination: seen before that point, not after
)

// finding is where locate thinks a probe died, and why.
type finding struct {
	where      string
	mechanism  string // xdp, tc, netfilter, rp_filter, conntrack, listen_queue, nic, network, ...
	confidence string
	culprit    string // the rule, program or counter, when known
	evidence   []string
}

// side is one node's observation, or why there isn't one.
type side struct {
	label string
	ok    bool
	why   string
	inv   node.Inventory
	obs   node.Observed
}

func (s side) has(what string) bool {
	for _, h := range s.inv.Have {
		if h == what {
			return true
		}
	}
	return false
}

const (
	burstSize      = 3
	locateBaseline = 2 * time.Second
)

// locate works out where probes to proto/port die: it watches both nodes
// (captures, kernel drop trace, drop counters), sends a small burst of
// probes, and reads the observations against each other.
func (p *prober) locate(proto node.Proto, ip string, port int) {
	name := fmt.Sprintf("locate %s/%d", proto, port)
	spec := node.ObserveSpec{Proto: proto, Port: port, Baseline: locateBaseline, Lifetime: 90 * time.Second}

	sides := []*side{{label: p.src.Label}, {label: p.dst.Label}}
	obs := make([]node.Observation, 2)
	var wg sync.WaitGroup
	for i, n := range []node.Node{p.src.Node, p.dst.Node} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := n.Observe(p.ctx, spec)
			if err != nil {
				sides[i].why = strings.TrimPrefix(err.Error(), node.ErrUnsupported.Error()+": ")
				return
			}
			obs[i], sides[i].ok, sides[i].inv = o, true, o.Inventory()
		}()
	}
	wg.Wait()
	if !sides[0].ok && !sides[1].ok {
		p.d.add(name, "locate.unsupported", Skip, "can't observe either side: %s: %s; %s: %s",
			sides[0].label, sides[0].why, sides[1].label, sides[1].why)
		return
	}

	lst, _ := p.dst.Node.Listen(p.ctx, proto, port, ip, p.opt.ConnectTimeout+10*time.Second)
	dials := make([]node.Dial, burstSize)
	for i := range dials {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dials[i], _ = p.src.Node.Dial(p.ctx, proto, ip, port, p.opt.ConnectTimeout)
		}()
	}
	wg.Wait()
	for i, o := range obs {
		if o == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := o.Stop(p.ctx)
			if err != nil {
				sides[i].ok, sides[i].why = false, err.Error()
				return
			}
			sides[i].obs = r
		}()
	}
	wg.Wait()
	if lst != nil {
		lst.Close()
	}

	f := analyze(proto, port, ip, *sides[0], *sides[1], dials)
	st := Fail
	if f.where == whereUnknown {
		st = Info
	}
	detail := fmt.Sprintf("%s (%s)", describe(f, p.src.Label, p.dst.Label), f.confidence)
	if f.culprit != "" {
		detail += ": " + f.culprit
	}
	c := p.d.add(name, "drop."+f.where, st, "%s", detail)
	c.Where, c.Mechanism, c.Confidence, c.Culprit = f.where, f.mechanism, f.confidence, f.culprit
	c.Lines = f.evidence
}

func describe(f finding, src, dst string) string {
	where := map[string]string{
		whereSrcEgress:  "dropped on " + src + " before it left",
		wherePath:       "dropped between " + src + " and " + dst,
		whereDstNIC:     "dropped by " + dst + "'s NIC or driver",
		whereDstXDP:     "dropped by XDP on " + dst,
		whereDstIngress: "dropped on " + dst + " before reaching the socket",
		whereDstEgress:  dst + "'s reply dropped on " + dst + " before it left",
		whereReturnPath: dst + "'s reply dropped between " + dst + " and " + src,
		whereSrcIngress: dst + "'s reply dropped on " + src,
		whereUnknown:    "could not tell where the probes were lost",
	}[f.where]
	if f.mechanism != "" && f.mechanism != "unknown" {
		where += " by " + f.mechanism
	}
	return where
}

// analyze reads two observations of the same burst against each other.
func analyze(proto node.Proto, port int, dstIP string, a, b side, dials []node.Dial) finding {
	var ev []string
	add := func(format string, args ...any) { ev = append(ev, fmt.Sprintf(format, args...)) }
	fwd := func(p node.Packet) bool { return p.Proto == string(proto) && p.DstPort == port }
	rev := func(p node.Packet) bool { return p.Proto == string(proto) && p.SrcPort == port }
	count := func(s side, match func(node.Packet) bool) int {
		n := 0
		for _, p := range s.obs.Packets {
			if match(p) {
				n++
			}
		}
		return n
	}
	for _, s := range []side{a, b} {
		if !s.ok {
			add("%s: not observed (%s)", s.label, s.why)
		}
		for _, m := range s.inv.Missing {
			add("%s: %s", s.label, m)
		}
	}

	// The source's own kernel may have refused outright.
	for _, d := range dials {
		if m := strings.ToLower(d.Msg); strings.Contains(m, "not permitted") || strings.Contains(m, "permission denied") {
			add("%s: the connect itself failed: %s", a.label, d.Msg)
			f := blame(a, false, whereSrcEgress, ev)
			if f.mechanism == "" {
				f.mechanism, f.confidence = "local_policy", observed
				f.culprit = "connect() refused locally (cgroup connect eBPF, LSM, or an OUTPUT rule)"
			}
			return f
		}
	}

	aCap, bCap := a.ok && a.has("capture"), b.ok && b.has("capture")
	aOut, aIn, bIn, bOut := count(a, fwd), count(a, rev), count(b, fwd), count(b, rev)
	if aCap {
		add("%s's capture: %d probe packet(s) out, %d reply packet(s) in", a.label, aOut, aIn)
	}
	if bCap {
		add("%s's capture: %d probe packet(s) in, %d reply packet(s) out", b.label, bIn, bOut)
	}
	for _, s := range []side{a, b} {
		for _, p := range s.obs.Packets {
			if p.Proto == "icmp" {
				add("%s's capture: %s from %s", s.label, p.Info, p.Src)
			}
		}
	}
	ev = elsewhere(a, b, port, ev)
	probe := func(d node.Drop) bool { return d.DstPort == port }
	reply := func(d node.Drop) bool { return d.SrcPort == port }

	// The captures say which stretch of the way the probes died on; drop
	// traces and counters then say what did it, on that stretch only. A
	// drop elsewhere is a consequence, not the cause: with the SYN-ACK lost
	// on the way back, the destination drops the retried SYNs, correctly.
	switch {
	case aCap && aOut == 0:
		if f, ok := traced(a, probe, whereSrcEgress, ev); ok {
			return f
		}
		return blame(a, true, whereSrcEgress, ev)
	case bCap && bIn == 0 && aCap && aIn > 0:
		return finding{where: wherePath, mechanism: "intercepted", confidence: observed,
			culprit:  fmt.Sprintf("replies came back but %s never received a probe: a proxy, DNAT, or another host answers for %s", b.label, dstIP),
			evidence: ev}
	case bCap && bIn == 0 && (aOut > 0 || !aCap):
		for _, p := range a.obs.Packets {
			if p.Proto == "icmp" && p.Src != dstIP {
				return finding{where: wherePath, mechanism: "network_reject", confidence: observed,
					culprit: fmt.Sprintf("%s answered: %s", p.Src, p.Info), evidence: ev}
			}
		}
		// Only what sits before the capture can explain this.
		if f, ok := traced(b, probe, whereDstXDP, ev); ok && f.mechanism == "xdp" {
			return f
		}
		if f := blame(b, false, whereDstXDP, ev, "xdp", "nic"); f.mechanism != "" {
			if f.mechanism == "nic" {
				f.where = whereDstNIC
			}
			return f
		}
		for _, h := range b.inv.Hooks {
			if h.Kind == "xdp" {
				ev = append(ev, fmt.Sprintf("%s has XDP on %s (%s); it runs before the capture, and native XDP drops leave no trace",
					b.label, h.Where, h.Detail))
				return finding{where: whereUnknown, mechanism: "xdp_or_network", confidence: inferred,
					culprit: fmt.Sprintf("XDP on %s's %s, or the network before it", b.label, h.Where), evidence: ev}
			}
		}
		return finding{where: wherePath, mechanism: "network", confidence: inferred,
			culprit: "security group, ACL or firewall between the two", evidence: ev}
	case bCap && bIn > 0 && bOut == 0:
		if f, ok := traced(b, probe, whereDstIngress, ev); ok {
			return f
		}
		if f, ok := traced(b, reply, whereDstEgress, ev); ok {
			return f
		}
		return blame(b, true, whereDstIngress, ev)
	case bCap && bOut > 0 && aCap && aIn == 0:
		// Seen leaving B, never seen on A: the network, or whatever on A
		// sits before its capture.
		if f, ok := traced(a, reply, whereSrcIngress, ev); ok && f.mechanism == "xdp" {
			return f
		}
		if f := blame(a, false, whereSrcIngress, ev, "xdp", "nic"); f.mechanism != "" {
			return f
		}
		return finding{where: whereReturnPath, mechanism: "network", confidence: inferred,
			culprit: "the way back is filtered: asymmetric routing through a stateful firewall is the usual cause", evidence: ev}
	case aCap && aIn > 0:
		for _, p := range a.obs.Packets {
			if rev(p) && strings.Contains(p.Flags, "R") {
				rejecter := "something in between"
				if bCap && bOut > 0 {
					rejecter = b.label
				}
				f := blame(b, false, whereDstIngress, ev)
				f.mechanism, f.confidence = "reject", observed
				if f.culprit == "" {
					f.culprit = "TCP reset sent by " + rejecter
				}
				return f
			}
		}
		if f, ok := traced(a, reply, whereSrcIngress, ev); ok {
			return f
		}
		return blame(a, false, whereSrcIngress, ev)
	}

	// Without captures to go by, any drop of ours the kernel reported.
	for _, c := range []struct {
		s     side
		match func(node.Drop) bool
		where string
	}{{b, probe, whereDstIngress}, {b, reply, whereDstEgress}, {a, probe, whereSrcEgress}, {a, reply, whereSrcIngress}} {
		if f, ok := traced(c.s, c.match, c.where, ev); ok {
			if f.mechanism == "xdp" && c.where == whereDstIngress {
				f.where = whereDstXDP
			}
			return f
		}
	}
	for _, s := range []side{b, a} {
		if f := blame(s, false, whereUnknown, ev); f.mechanism != "" {
			return f
		}
	}
	f := finding{where: whereUnknown, confidence: inferred, evidence: ev}
	if aCap && aOut > 0 && !b.ok {
		f.culprit = fmt.Sprintf("the probes left %s; past that, %s would have to be observable to say more", a.label, b.label)
	}
	return f
}

// elsewhere notes drops of our packets in other network namespaces on the
// same machines: not the node's own, but worth knowing about.
func elsewhere(a, b side, port int, ev []string) []string {
	for _, s := range []side{a, b} {
		n := map[string]int{}
		var order []string
		for _, d := range s.obs.Drops {
			if d.OtherNetns && (d.DstPort == port || d.SrcPort == port) {
				k := fmt.Sprintf("%s (%s)", d.Location, d.Reason)
				if n[k] == 0 {
					order = append(order, k)
				}
				n[k]++
			}
		}
		for _, k := range order {
			ev = append(ev, fmt.Sprintf("%s's kernel dropped %d in %s, but in another network namespace there (a container?)",
				s.label, n[k], k))
		}
	}
	return ev
}

// traced looks for drops of our packets on s that match, in s's own
// network namespace. Drops the TCP stack makes as part of its normal work
// (a retried SYN it already answered) don't count as a cause.
func traced(s side, match func(node.Drop) bool, where string, ev []string) (finding, bool) {
	for _, d := range s.obs.Drops {
		if d.OtherNetns || !match(d) {
			continue
		}
		mech := mechanismOf(d)
		for _, c := range moved(s) {
			// Without a drop reason (older kernels) the location can be a
			// generic function; a counter that moved says which it was.
			if mech == "kernel" && counterMechanism(c) != "" {
				mech = counterMechanism(c)
			}
		}
		if mech == "kernel" && strings.HasPrefix(d.Location, "tcp_") {
			continue
		}
		n := 0
		for _, e := range s.obs.Drops {
			if !e.OtherNetns && match(e) && e.Location == d.Location && e.Reason == d.Reason {
				n++
			}
		}
		reason := d.Reason
		if reason == "" {
			reason = "no reason on this kernel"
		}
		ev = append(ev, fmt.Sprintf("%s's kernel dropped %d of our packets in %s (%s)", s.label, n, d.Location, reason))
		f := finding{where: where, mechanism: mech, confidence: observed,
			culprit: fmt.Sprintf("%s in %s", reason, d.Location), evidence: ev}
		// A counter of the same kind names the rule or program; failing
		// that, list what is attached that could be it.
		for _, c := range moved(s) {
			if counterMechanism(c) == mech {
				f.culprit += "; " + counterCulprit(c)
				f.evidence = append(f.evidence, fmt.Sprintf("%s: %s %s %s moved by %d (%d in the quiet window before)",
					s.label, c.Kind, c.Scope, c.Name, c.Delta, c.Baseline))
				return f, true
			}
		}
		if c := culprits(s, mech); c != "" {
			f.culprit += "; " + c
		}
		return f, true
	}
	return finding{}, false
}

// mechanismOf names what dropped a traced packet, from the drop reason
// (5.17+) or failing that the function it was dropped in.
func mechanismOf(d node.Drop) string {
	r, l := d.Reason, d.Location
	switch {
	case r == "XDP" || strings.Contains(l, "xdp"):
		return "xdp"
	case strings.HasPrefix(r, "TC_") || strings.HasPrefix(l, "tcf_") || strings.HasPrefix(l, "sch_handle_") || strings.HasPrefix(l, "tcx_"):
		return "tc"
	case r == "NETFILTER_DROP" || strings.HasPrefix(l, "nf_") || strings.HasPrefix(l, "nft_") || strings.HasPrefix(l, "ipt_") || strings.HasPrefix(l, "ip6t_"):
		return "netfilter"
	case r == "IP_RPFILTER":
		return "rp_filter"
	case strings.HasPrefix(r, "BPF_CGROUP") || r == "SOCKET_FILTER" || strings.Contains(l, "sk_filter"):
		return "cgroup_bpf"
	case strings.Contains(r, "LISTEN_OVERFLOW") || strings.Contains(r, "SOCKET_BACKLOG"):
		return "listen_queue"
	case strings.HasPrefix(r, "NF_CONNTRACK") || strings.Contains(l, "conntrack"):
		return "conntrack"
	}
	return "kernel"
}

// blame explains a drop on s from the counters that moved there, limited
// to mechanisms if any are given. strong asks for a finding even when no
// counter moved: "somewhere on s", inferred, with the candidates listed.
func blame(s side, strong bool, where string, ev []string, mechanisms ...string) finding {
	f := finding{where: where, evidence: ev}
	for _, c := range moved(s) {
		f.evidence = append(f.evidence, fmt.Sprintf("%s: %s %s %s moved by %d (%d in the quiet window before)",
			s.label, c.Kind, c.Scope, c.Name, c.Delta, c.Baseline))
		mech := counterMechanism(c)
		if f.mechanism != "" || mech == "" || (len(mechanisms) > 0 && !slices.Contains(mechanisms, mech)) {
			continue
		}
		f.mechanism, f.confidence, f.culprit = mech, counted, counterCulprit(c)
	}
	if f.mechanism == "" && strong {
		f.mechanism, f.confidence, f.culprit = "unknown", inferred, culprits(s, "")
	}
	return f
}

// moved returns s's counters that moved with our probes rather than with
// background traffic: more than twice the quiet window's movement.
func moved(s side) []node.Counter {
	var out []node.Counter
	for _, c := range s.obs.Counters {
		if c.Delta > 2*c.Baseline {
			out = append(out, c)
		}
	}
	// Firewall rules first: they name the exact culprit.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind == "fw" && out[j].Kind != "fw" })
	return out
}

func counterMechanism(c node.Counter) string {
	n := strings.ToLower(c.Name)
	switch c.Kind {
	case "fw":
		return "netfilter"
	case "tc":
		if c.Name == "clsact" || c.Name == "ingress" {
			return "tc"
		}
		return "qdisc"
	case "conntrack":
		return "conntrack"
	case "nic":
		if strings.Contains(n, "xdp") {
			return "xdp"
		}
		return "nic"
	case "stat":
		switch c.Name {
		case "IPReversePathFilter":
			return "rp_filter"
		case "ListenOverflows", "ListenDrops", "TCPReqQFullDrop", "TCPBacklogDrop":
			return "listen_queue"
		case "PAWSPassive", "PAWSActive", "PAWSEstabRejected":
			return "tcp_timestamps"
		case "RcvbufErrors", "InCsumErrors":
			return "udp_socket"
		}
	}
	return ""
}

func counterCulprit(c node.Counter) string {
	switch c.Kind {
	case "fw":
		return fmt.Sprintf("%s: %s", c.Scope, c.Name)
	case "tc":
		return fmt.Sprintf("tc %s on %s dropped %d", c.Name, c.Scope, c.Delta)
	case "nic":
		return fmt.Sprintf("%s %s +%d", c.Scope, c.Name, c.Delta)
	case "stat":
		hint := map[string]string{
			"IPReversePathFilter": " (reverse path filter: the reply route to the sender goes out another interface)",
			"ListenOverflows":     " (the service isn't accepting fast enough)",
			"PAWSPassive":         " (tcp_tw_recycle / timestamps behind NAT)",
		}[c.Name]
		return fmt.Sprintf("%s %s +%d%s", c.Scope, c.Name, c.Delta, hint)
	}
	return fmt.Sprintf("%s %s %s +%d", c.Kind, c.Scope, c.Name, c.Delta)
}

// culprits lists what on s could have done it, when nothing says what did.
func culprits(s side, mech string) string {
	var out []string
	for _, h := range s.inv.Hooks {
		if mech == "" || strings.HasPrefix(h.Kind, mech) || (mech == "tc" && strings.HasPrefix(h.Kind, "tcx")) {
			out = append(out, fmt.Sprintf("%s on %s (%s)", h.Kind, h.Where, h.Detail))
		}
	}
	if mech == "" {
		out = append(out, s.inv.Policies...)
		for dev, v := range s.inv.RPFilter {
			out = append(out, fmt.Sprintf("rp_filter=%d on %s", v, dev))
		}
		sort.Strings(out)
	}
	if len(out) == 0 {
		return ""
	}
	return "candidates on " + s.label + ": " + strings.Join(out, ", ")
}
