// The --json stdout contract, version 1. CLI-JSON.md is the normative doc; the
// shape here must not change without a version bump there. Machine consumers
// (the Python bindings) parse THIS, never the human output — exit codes are
// shared with the human mode and stay the SPEC.md §9 contract.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/JsizzleR/surfacelock"
)

// jsonContractVersion is bumped on any breaking change to the report shape.
// Adding fields is not breaking: consumers must ignore fields they do not know
// (the opposite of the lockfile's §7 strictness — a report is advice, an
// artifact is an authority).
const jsonContractVersion = 1

type jsonReport struct {
	Version int    `json:"surfacelock_json"`
	Verb    string `json:"verb"`
	File    string `json:"file"`
	Exit    int    `json:"exit"`
	// Error is a run-level failure that prevented per-server work (unreadable
	// lockfile, usage error). Sanitized: error text can carry server bytes.
	Error string `json:"error,omitempty"`

	// lock only.
	Name        string `json:"name,omitempty"`
	Tools       *int   `json:"tools,omitempty"`
	Era         string `json:"era,omitempty"`
	SurfaceHash string `json:"surface_hash,omitempty"`

	// verify/diff: one entry per server processed this run.
	Servers map[string]*jsonServer `json:"servers,omitempty"`
}

type jsonServer struct {
	// Outcome is this entry's own verdict: "ok", "drift", "transport",
	// "lockfile", or "inadmissible". The run's exit code is the WORST outcome
	// across entries (worse() precedence), so a drift found beside a transport
	// failure is still reported here — the exit alone cannot carry both.
	Outcome string    `json:"outcome"`
	Error   string    `json:"error,omitempty"` // sanitized; absent on ok/drift
	Tools   *int      `json:"tools,omitempty"` // ok: locked tool count
	Era     string    `json:"era,omitempty"`   // ok: locked era
	Diff    *jsonDiff `json:"diff,omitempty"`  // drift only
}

// jsonDiff mirrors surfacelock.SurfaceDiff. Severity and class order come from
// the Go classifier; a consumer adds no judgment of its own.
type jsonDiff struct {
	Severity            string         `json:"severity"`
	EraChanged          bool           `json:"era_changed"`
	OldEra              string         `json:"old_era"`
	NewEra              string         `json:"new_era"`
	InstructionsChanged bool           `json:"instructions_changed"`
	Tools               []jsonToolDiff `json:"tools"`
}

type jsonToolDiff struct {
	Name    string   `json:"name"`
	Classes []string `json:"classes"` // most severe first, never empty
}

func diffToJSON(d *surfacelock.SurfaceDiff) *jsonDiff {
	out := &jsonDiff{
		Severity:            d.Severity().String(),
		EraChanged:          d.EraChanged,
		OldEra:              d.OldEra,
		NewEra:              d.NewEra,
		InstructionsChanged: d.InstructionsChanged,
		Tools:               []jsonToolDiff{},
	}
	for _, t := range d.Tools {
		classes := make([]string, len(t.Classes))
		for i, cl := range t.Classes {
			classes[i] = cl.String()
		}
		out.Tools = append(out.Tools, jsonToolDiff{Name: t.Name, Classes: classes})
	}
	return out
}

func outcomeFor(code int) string {
	switch code {
	case exitOK:
		return "ok"
	case exitDrift:
		return "drift"
	case exitLockfile:
		return "lockfile"
	case exitInadmissible:
		return "inadmissible"
	default:
		return "transport"
	}
}

func (c *cli) newReport(verb string) *jsonReport {
	return &jsonReport{Version: jsonContractVersion, Verb: verb, File: c.file}
}

// finish stamps the exit code, emits the report if --json, and returns the code
// — every post-flag-parse return path in a --json run goes through here, so
// stdout carries exactly one JSON document per run.
func (c *cli) finish(rep *jsonReport, code int) int {
	rep.Exit = code
	if !c.jsonOut {
		return code
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		// A report that cannot render must not exit 0 pretending it did.
		c.errorf("render --json report: %v", err)
		if code == exitOK {
			code = exitTransport
		}
		return code
	}
	fmt.Fprintf(c.stdout, "%s\n", b)
	return code
}

// fail records a sanitized run-level error and finishes.
func (c *cli) fail(rep *jsonReport, code int, err error) int {
	rep.Error = safe(err.Error())
	return c.finish(rep, code)
}
