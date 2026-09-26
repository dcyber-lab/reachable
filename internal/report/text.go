// Package report renders probe results for a terminal.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/dcyber-lab/reachable/internal/probe"
)

// Printer writes human-readable output, optionally with ANSI colors.
type Printer struct {
	W     io.Writer
	Color bool
}

func (p Printer) paint(code, s string) string {
	if !p.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

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
		return p.paint("2", label)
	}
}

// Side prints what we learned about one machine.
func (p Printer) Side(s *probe.Side) {
	f := s.Facts
	var addrs []string
	for _, a := range f.Addrs {
		addrs = append(addrs, a.IP+"@"+a.Dev)
	}
	fmt.Fprintf(p.W, "%s  %s  %s@%s  %s %s\n", p.paint("1", s.Label), s.Target, f.User, f.Hostname, f.Arch, f.Kernel)
	fmt.Fprintf(p.W, "   dialed as %s; addrs: %s\n", s.Addr, orNone(addrs))
	fmt.Fprintf(p.W, "   can use: %s\n", orNone(f.Capabilities))
}

func orNone(xs []string) string {
	if len(xs) == 0 {
		return "(none found)"
	}
	return strings.Join(xs, " ")
}

// Direction prints one src -> dst result.
func (p Printer) Direction(d *probe.Direction) {
	target := d.Target
	if d.IP != "" && d.IP != d.Target {
		target += " (" + d.IP + ")"
	}
	fmt.Fprintf(p.W, "\n%s  %s\n", p.paint("1", d.From+" -> "+d.To), target)
	for _, c := range d.Checks {
		fmt.Fprintf(p.W, "  %s  %-9s %s\n", p.status(c.Status), c.Name, c.Detail)
		for _, l := range c.Lines {
			fmt.Fprintf(p.W, "              %s\n", p.paint("2", l))
		}
	}
	code := "31;1"
	if d.OK {
		code = "32;1"
	}
	fmt.Fprintf(p.W, "  => %s\n", p.paint(code, d.Verdict))
}
