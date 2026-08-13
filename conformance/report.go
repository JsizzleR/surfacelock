package conformance

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Check probes a target and grades it against era — the minimal library
// surface a lockfile consumer needs to validate an entry's era tag: the lock
// records `protocol.era`; Check answers whether the live server actually
// conforms to the revision that tag names.
func Check(ctx context.Context, target string, dial Dialer, era string) (*Report, error) {
	if !contains(Eras, era) {
		return nil, fmt.Errorf("unknown era %q (known: %s)", era, strings.Join(Eras, ", "))
	}
	cap, err := Probe(ctx, target, dial, era)
	if err != nil {
		return nil, err
	}
	return Grade(cap), nil
}

// ValidateEraClaim turns a report into the era-tag verdict: nil only when the
// target demonstrably conforms (star-conformance included — SHOULD violations
// are reported, never fatal, per PREDICATES.md). UNGRADED is an error, not a
// pass: a dead target must never validate a claim (silence is not conformance).
func ValidateEraClaim(r *Report) error {
	switch r.Verdict {
	case Conformant, ConformantStar:
		return nil
	case Ungraded:
		return fmt.Errorf("era claim %s unsubstantiable for %s: every cell unreached (target unreachable or refusing)", r.Era, r.Target)
	default:
		var v []string
		for _, c := range r.Cells {
			if c.Outcome == MustViolation {
				v = append(v, c.Probe+": "+c.Evidence)
			}
		}
		return fmt.Errorf("%s does not conform to era %s: %s", r.Target, r.Era, strings.Join(v, "; "))
	}
}

// probeOrder fixes the matrix's column order (grading order varies by era).
var probeOrder = []string{
	"H1.init", "H2.newer", "H3.cold", "D1.discover", "D2.nometa",
	"V1.header", "V1.noheader", "V2.mismatch", "S1.session", "S2.nosession",
	"T1.tools", "T2.badcursor", "B1.batch", "C1.cacheable", "R1.resulttype",
	"G1.get", "I1.identity",
}

func shortOutcome(o Outcome) string {
	switch o {
	case Pass:
		return "pass"
	case MustViolation:
		return "MUST!"
	case ShouldViolation:
		return "should!"
	case Observed:
		return "obs"
	case NotApplicable:
		return "na"
	default:
		return "unreached"
	}
}

// RenderMatrixTSV emits the machine face: one row per (target, era), one
// column per predicate, plus the verdict.
func RenderMatrixTSV(reports []*Report) string {
	var b strings.Builder
	b.WriteString("target\tkind\tera\tverdict")
	for _, p := range probeOrder {
		b.WriteString("\t" + p)
	}
	b.WriteString("\n")
	for _, r := range sorted(reports) {
		cells := map[string]Cell{}
		for _, c := range r.Cells {
			cells[c.Probe] = c
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s", r.Target, r.Kind, r.Era, r.Verdict)
		for _, p := range probeOrder {
			if c, ok := cells[p]; ok {
				b.WriteString("\t" + shortOutcome(c.Outcome))
			} else {
				b.WriteString("\t-")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// RenderMatrixMD emits the human face: the verdict table, then per-target
// evidence for every violation and unreached cell (no silent gaps — an
// unreached probe is always visible).
func RenderMatrixMD(reports []*Report) string {
	var b strings.Builder
	b.WriteString("# MCP era-conformance matrix\n\n")
	b.WriteString("Generated from the retained captures by `conformance/gen` — never hand-edited.\n")
	b.WriteString("Predicates and verdict model: `conformance/PREDICATES.md` (pre-registered).\n\n")
	b.WriteString("| target | kind | era | verdict | MUST violations | SHOULD violations | unreached |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, r := range sorted(reports) {
		var must, should, unreached []string
		for _, c := range r.Cells {
			switch c.Outcome {
			case MustViolation:
				must = append(must, c.Probe)
			case ShouldViolation:
				should = append(should, c.Probe)
			case Unreached:
				unreached = append(unreached, c.Probe)
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
			r.Target, r.Kind, r.Era, r.Verdict, orDash(must), orDash(should), orDash(unreached))
	}
	b.WriteString("\n## Evidence (violations and unreached cells)\n")
	for _, r := range sorted(reports) {
		var lines []string
		for _, c := range r.Cells {
			if c.Outcome == MustViolation || c.Outcome == ShouldViolation || c.Outcome == Unreached {
				lines = append(lines, fmt.Sprintf("- `%s` %s — %s", c.Probe, shortOutcome(c.Outcome), c.Evidence))
			}
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n### %s @ %s\n\n%s\n", r.Target, r.Era, strings.Join(lines, "\n"))
	}
	return b.String()
}

func orDash(xs []string) string {
	if len(xs) == 0 {
		return "—"
	}
	return strings.Join(xs, ", ")
}

func sorted(reports []*Report) []*Report {
	out := append([]*Report(nil), reports...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Era < out[j].Era
	})
	return out
}
