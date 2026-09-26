package report

import "github.com/dcyber-lab/reachable/internal/probe"

// SchemaVersion is bumped whenever Document changes incompatibly.
const SchemaVersion = 1

// Document is a whole run, as -json prints it.
type Document struct {
	SchemaVersion int                `json:"schema_version"`
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Version       string             `json:"version,omitempty"`
	Hosts         []*probe.Side      `json:"hosts,omitempty"`
	Directions    []*probe.Direction `json:"directions,omitempty"`
}
