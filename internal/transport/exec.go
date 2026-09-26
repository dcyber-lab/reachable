// Package transport gets scripts onto machines: shell.Runners and the
// node.Backends built on them.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/dcyber-lab/reachable/internal/node/shell"
)

// execRunner runs scripts through a local command that reads the script on
// stdin: `bash -s --` itself, or `ssh host bash -s --`.
type execRunner struct {
	argv    []string // command prefix; script arguments are appended
	onClose func()
}

func (r *execRunner) command(ctx context.Context, script string, args []string) *exec.Cmd {
	argv := append(append([]string{}, r.argv...), args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(script)
	return cmd
}

func (r *execRunner) Run(ctx context.Context, script string, args []string) (string, error) {
	cmd := r.command(ctx, script, args)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if msg := strings.TrimSpace(errb.String()); msg != "" && errors.As(err, &ee) {
			return out.String(), fmt.Errorf("%s: %s", r.argv[0], msg)
		}
		return out.String(), fmt.Errorf("%s: %w", r.argv[0], err)
	}
	return out.String(), nil
}

func (r *execRunner) Start(ctx context.Context, script string, args []string) (shell.Stream, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := r.command(ctx, script, args)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	// Leave Stderr nil (/dev/null) rather than io.Discard, which would need
	// a copying goroutine for Wait to wait on. Over a multiplexed ssh
	// connection the master holds on to the client's pipes until the remote
	// script exits, so Wait would block for the script's whole lifetime
	// after we have stopped caring. WaitDelay covers stdout the same way.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	s := &stream{cmd: cmd, cancel: cancel, lines: make(chan string, 64)}
	go func() {
		defer close(s.lines)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			select {
			case s.lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return s, nil
}

func (r *execRunner) Close() error {
	if r.onClose != nil {
		r.onClose()
	}
	return nil
}

type stream struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	lines  chan string
}

func (s *stream) Next(timeout time.Duration) (string, bool) {
	select {
	case l, ok := <-s.lines:
		return l, ok
	case <-time.After(timeout):
		return "", false
	}
}

func (s *stream) Close() {
	s.cancel()
	_ = s.cmd.Wait()
}
