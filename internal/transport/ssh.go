package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/dcyber-lab/reachable/internal/node"
	"github.com/dcyber-lab/reachable/internal/node/shell"
)

// SSH reaches machines with the system ssh binary, so ~/.ssh/config,
// ProxyJump, agents, certificates and known_hosts behave exactly as they do
// for `ssh host`. Each host gets one master connection, opened up front, and
// every script is multiplexed over it.
type SSH struct {
	// Args are passed to every ssh invocation, e.g. {"-p", "2222"}.
	Args []string
	// Interactive lets the master connection prompt on the terminal
	// (passwords, 2FA, host keys). Off, ssh runs with BatchMode and fails
	// instead of waiting for input nobody will type, which is what a
	// program calling reachable wants.
	Interactive bool

	ctlDir string
}

var _ node.Backend = (*SSH)(nil)

// Open connects to target, anything ssh accepts: an alias, user@host, ...
// The address other nodes should dial is the HostName `ssh -G` resolves
// target to.
func (s *SSH) Open(ctx context.Context, target string) (node.Node, string, error) {
	if s.ctlDir == "" {
		// Unix socket paths are limited to ~104 bytes and $TMPDIR on macOS
		// eats most of that, so keep the control sockets under /tmp.
		dir, err := os.MkdirTemp("/tmp", "reachable-")
		if err != nil {
			return nil, "", err
		}
		s.ctlDir = dir
	}
	addr, err := s.hostname(target)
	if err != nil {
		return nil, "", err
	}
	base := append([]string{
		"-o", "ControlPath=" + s.ctlDir + "/%C",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=3",
	}, s.Args...)

	master := append(append([]string{}, base...), "-o", "ControlMaster=yes", "-o", "ControlPersist=300", "-f", "-N")
	if !s.Interactive {
		master = append(master, "-o", "BatchMode=yes")
	}
	var errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "ssh", append(master, target)...)
	if s.Interactive {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	} else {
		cmd.Stdout, cmd.Stderr = io.Discard, &errb
	}
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, "", fmt.Errorf("ssh %s: %s", target, msg)
		}
		return nil, "", fmt.Errorf("ssh %s: %w", target, err)
	}

	r := &execRunner{
		argv: append(append(append([]string{"ssh"}, base...), "-o", "BatchMode=yes", "-T", target), "bash", "-s", "--"),
		onClose: func() {
			exit := exec.Command("ssh", append(append(append([]string{}, base...), "-O", "exit"), target)...)
			exit.Stdout, exit.Stderr = io.Discard, io.Discard
			_ = exit.Run()
		},
	}
	return shell.New(r), addr, nil
}

// Close removes the control socket directory. Close the nodes first.
func (s *SSH) Close() {
	if s.ctlDir != "" {
		os.RemoveAll(s.ctlDir)
	}
}

func (s *SSH) hostname(target string) (string, error) {
	out, err := exec.Command("ssh", append(append([]string{}, s.Args...), "-G", target)...).Output()
	if err != nil {
		return "", fmt.Errorf("ssh -G %s: %w", target, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == "hostname" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("ssh -G %s: no hostname", target)
}
