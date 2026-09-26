package transport

import (
	"context"
	"fmt"

	"github.com/dcyber-lab/reachable/internal/node"
	"github.com/dcyber-lab/reachable/internal/node/shell"
)

// Local is the machine reachable itself runs on, as target "local://".
// It needs bash, like any shell node.
type Local struct{}

var _ node.Backend = Local{}

// Open returns the local node. It has no idea which of its addresses the
// other side should dial, so it returns "".
func (Local) Open(_ context.Context, target string) (node.Node, string, error) {
	if target != "" {
		return nil, "", fmt.Errorf("local://%s: local takes no target, write local://", target)
	}
	return shell.New(&execRunner{argv: []string{"bash", "-s", "--"}}), "", nil
}
