// Package report renders probe results for a terminal.
package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/dcyber-lab/reachable/internal/probe"
)

// Printer writes human-readable output, optionally with ANSI colors.
type Printer struct {
	W     io.Writer
	Color bool
	// Verbose adds the evidence behind each located drop.
	Verbose bool
}

func (p Printer) paint(code, s string) string {
	if !p.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Printer) bold(s string) string { return p.paint("1", s) }
func (p Printer) dim(s string) string  { return p.paint("2", s) }

func (p Printer) status(st probe.Status) string {
	label := fmt.Sprintf("%-4s", st)
	switch st {
	case probe.OK:
		return p.paint("32", label)
	case probe.Warn:
		return p.paint("33", label)
	case probe.Fail:
		return p.paint("31;1", label)
	default:
		return p.dim(label)
	}
}

// glyph is a one-character status: ✓ ! ✗ –.
func (p Printer) glyph(st probe.Status) string {
	switch st {
	case probe.OK:
		return p.paint("32", "✓")
	case probe.Warn:
		return p.paint("33", "!")
	case probe.Fail:
		return p.paint("31;1", "✗")
	default:
		return p.dim("–")
	}
}

func (p Printer) result(r probe.Result) string {
	s := fmt.Sprintf("%-11s", strings.ToUpper(string(r)))
	switch r {
	case probe.Reachable:
		return p.paint("32;1", s)
	case probe.Partial:
		return p.paint("33;1", s)
	default:
		return p.paint("31;1", s)
	}
}

// Side prints what we learned about one machine.
func (p Printer) Side(s *probe.Side) {
	f := s.Facts
	var addrs []string
	for _, a := range f.Addrs {
		addrs = append(addrs, a.IP+"@"+a.Dev)
	}
	fmt.Fprintf(p.W, "%s  %s  %s@%s  %s %s\n", p.bold(s.Label), s.Target, f.User, f.Hostname, f.Arch, f.Kernel)
	fmt.Fprintf(p.W, "   dialed as %s; addrs: %s\n", s.Addr, orNone(addrs))
	fmt.Fprintf(p.W, "   can use: %s\n", orNone(f.Capabilities))
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "(none found)"
	}
	return strings.Join(xs, " ")
}

// located returns the "locate <port>" check of each port that has one.
func located(d *probe.Direction) map[string]probe.Check {
	m := map[string]probe.Check{}
	for _, c := range d.Checks {
		if port, ok := strings.CutPrefix(c.Name, "locate "); ok {
			m[port] = c
		}
	}
	return m
}

// Direction prints one src -> dst result, with each port's located drop
// right under the port.
func (p Printer) Direction(d *probe.Direction) {
	target := d.Target
	if d.IP != "" && d.IP != d.Target {
		target += " (" + d.IP + ")"
	}
	fmt.Fprintf(p.W, "\n%s  %s\n", p.bold(d.From+" -> "+d.To), target)
	loc := located(d)
	ports := map[string]bool{}
	for _, c := range d.Checks {
		ports[c.Name] = true
	}
	for _, c := range d.Checks {
		if port, ok := strings.CutPrefix(c.Name, "locate "); ok && ports[port] {
			continue // printed under its port
		}
		p.check(c)
		if l, ok := loc[c.Name]; ok {
			p.locateLines(l, "                  ", true)
		}
	}
	code := "31;1"
	if d.OK {
		code = "32;1"
	}
	fmt.Fprintf(p.W, "  => %s\n", p.paint(code, d.Verdict))
}

func (p Printer) check(c probe.Check) {
	fmt.Fprintf(p.W, "  %s  %-9s %s\n", p.status(c.Status), c.Name, c.Detail)
	if strings.HasPrefix(c.Name, "locate ") && !p.Verbose {
		return
	}
	for _, l := range c.Lines {
		fmt.Fprintf(p.W, "              %s\n", p.dim(l))
	}
}

// locateLines prints a located drop: the finding (unless the caller
// already did), the rule or program behind it, and with -v the evidence.
func (p Printer) locateLines(c probe.Check, indent string, withFinding bool) {
	if withFinding {
		fmt.Fprintf(p.W, "%s%s %s\n", indent, p.paint("36", "↳"), finding(c))
		indent += "  "
	}
	for _, line := range culprit(c) {
		fmt.Fprintf(p.W, "%s%s\n", indent, p.bold(line))
	}
	for _, line := range kernelSaid(c) {
		fmt.Fprintf(p.W, "%s%s\n", indent, p.dim(line))
	}
	if p.Verbose {
		for _, l := range c.Lines {
			fmt.Fprintf(p.W, "%s%s\n", indent, p.dim(l))
		}
	}
}

// finding is a locate check's headline, without the culprit.
func finding(c probe.Check) string {
	if c.Culprit == "" {
		return c.Detail
	}
	return strings.TrimSuffix(c.Detail, ": "+c.Culprit)
}

// culprit splits a locate check's culprit into what names the rule,
// program or cause (shown first) and what the kernel's drop trace said.
func culprit(c probe.Check) []string {
	var out []string
	for _, part := range strings.Split(c.Culprit, "; ") {
		if part != "" && !isKernelSaid(part) {
			out = append(out, part)
		}
	}
	return out
}

func kernelSaid(c probe.Check) []string {
	var out []string
	for _, part := range strings.Split(c.Culprit, "; ") {
		if isKernelSaid(part) {
			out = append(out, "kernel: "+part)
		}
	}
	return out
}

// isKernelSaid tells "NETFILTER_DROP in nft_do_chain" from a rule or hint.
func isKernelSaid(part string) bool {
	reason, _, ok := strings.Cut(part, " in ")
	return ok && (reason == "no reason on this kernel" || strings.ToUpper(reason) == reason && !strings.Contains(reason, " "))
}

// Summary closes a run: a line per direction with every port, then each
// problem once, located drops drawn on the packet's way.
func (p Printer) Summary(sides []*probe.Side, dirs []*probe.Direction) {
	name := map[string]string{}
	for _, s := range sides {
		name[s.Label] = s.Target
	}
	heads := make([]string, len(dirs))
	w := 0
	for i, d := range dirs {
		heads[i] = fmt.Sprintf("%s %s → %s %s", d.From, name[d.From], d.To, name[d.To])
		w = max(w, utf8.RuneCountInString(heads[i]))
	}

	rule := p.dim(strings.Repeat("─", 64))
	fmt.Fprintf(p.W, "\n%s\n %s\n%s\n", rule, p.bold("Summary"), rule)
	for i, d := range dirs {
		var ports []string
		for _, c := range d.Checks {
			if strings.HasPrefix(c.Name, "tcp/") || strings.HasPrefix(c.Name, "udp/") {
				ports = append(ports, p.glyph(c.Status)+" "+c.Name)
			}
		}
		pad := strings.Repeat(" ", w-utf8.RuneCountInString(heads[i]))
		fmt.Fprintf(p.W, " %s%s  %s %s\n", heads[i], pad, p.result(d.Result), strings.Join(ports, "  "))
	}

	// Each problem once: the same check failing the same way in both
	// directions is one line, A ⇄ B.
	type problem struct {
		c    probe.Check
		dirs string
		d    *probe.Direction
		loc  *probe.Check
	}
	var problems []*problem
	seen := map[string]*problem{}
	for _, d := range dirs {
		loc := located(d)
		for _, c := range d.Checks {
			if (c.Status != probe.Fail && c.Status != probe.Warn) || strings.HasPrefix(c.Name, "locate ") {
				continue
			}
			pr := &problem{c: c, dirs: d.From + " → " + d.To, d: d}
			if l, ok := loc[c.Name]; ok {
				pr.loc = &l
			} else if other, ok := seen[c.Name+"\x00"+c.Detail]; ok {
				other.dirs = other.d.From + " ⇄ " + other.d.To
				continue
			}
			seen[c.Name+"\x00"+c.Detail] = pr
			problems = append(problems, pr)
		}
	}
	if len(problems) > 0 {
		fmt.Fprintln(p.W)
	}
	for _, pr := range problems {
		detail := pr.c.Detail
		if pr.loc != nil {
			detail = finding(*pr.loc)
		}
		fmt.Fprintf(p.W, " %s %-9s %s  %s\n", p.glyph(pr.c.Status), pr.c.Name, p.dim(pr.dirs), detail)
		if pr.loc != nil {
			if s := p.strip(pr.loc.Where, pr.d.From, pr.d.To); s != "" {
				fmt.Fprintf(p.W, "     %s\n", s)
			}
			p.locateLines(*pr.loc, "     ", false)
		}
	}
	switch {
	case len(problems) == 0:
		fmt.Fprintf(p.W, "\n %s every tested port got through\n", p.glyph(probe.OK))
	case !p.Verbose && hasLocate(dirs):
		fmt.Fprintf(p.W, "\n %s\n", p.dim("-v shows the evidence behind each located drop"))
	}
	fmt.Fprintln(p.W, rule)
}

func hasLocate(dirs []*probe.Direction) bool {
	for _, d := range dirs {
		if len(located(d)) > 0 {
			return true
		}
	}
	return false
}

// The way a probe takes and the way its reply comes back, in the stretches
// locate names.
var (
	forward = []string{"src_egress", "path", "dst_nic", "dst_xdp", "dst_ingress"}
	back    = []string{"dst_egress", "return_path", "src_ingress"}
)

// strip draws the packet's way with ✗ where it died:
//
//	A out ── network ── B NIC ── B XDP ── B in ✗ ── B socket
func (p Printer) strip(where, src, dst string) string {
	labels := map[string]string{
		"src_egress": src + " out", "path": "network", "dst_nic": dst + " NIC",
		"dst_xdp": dst + " XDP", "dst_ingress": dst + " in",
		"dst_egress": dst + " out", "return_path": "network", "src_ingress": src + " in",
	}
	draw := func(lane []string, dead int, end string) string {
		var b strings.Builder
		for i, st := range lane {
			if i > 0 {
				b.WriteString(p.dim(" ── "))
			}
			switch {
			case dead < 0 || i < dead:
				b.WriteString(p.paint("32", labels[st]))
			case i == dead:
				b.WriteString(p.paint("31;1", labels[st]+" ✗"))
			default:
				b.WriteString(p.dim(labels[st]))
			}
		}
		if end != "" {
			b.WriteString(p.dim(" ── "))
			if dead >= 0 {
				b.WriteString(p.dim(end))
			} else {
				b.WriteString(p.paint("32", end))
			}
		}
		return b.String()
	}
	for i, st := range forward {
		if st == where {
			return draw(forward, i, dst+" socket")
		}
	}
	for i, st := range back {
		if st == where {
			return draw(forward, -1, dst+" socket") + "\n     " + p.dim("reply ") + draw(back, i, "")
		}
	}
	return ""
}
