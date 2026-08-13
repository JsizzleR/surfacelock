package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/JsizzleR/surfacelock"
)

// verifier holds the per-session verification state. All methods are called
// under the core's mutex; none of them do I/O — they return verdicts and
// finding lines and the router acts on them.
type verifier struct {
	entry *surfacelock.ServerLock
	name  string
	warn  bool
	lim   surfacelock.Limits

	lockTools map[string]*surfacelock.ToolLock

	// handshakeEra is the era the session's verified (or warn-forwarded)
	// handshake established; "" until then. Classic tools/list responses have no
	// era of their own, so they can only be verified once this is set.
	handshakeEra string

	// everClean flips when the first enumeration completes clean. Drift found
	// after that is MID-SESSION drift — the surface changed under a live
	// session, the loudest finding the proxy can produce — and is reported
	// distinctly from connect-time drift (a stale lock or a server that changed
	// between pin and connect).
	everClean bool

	nextEnumID int
}

// enumeration tracks one cursor-chained tools/list sequence. The client drives
// pagination; the proxy verifies whatever the client actually fetches, and only
// a fully-paginated enumeration earns a completeness verdict (removed-tool
// detection and the rollup comparison need the whole set).
type enumeration struct {
	id       int
	era      string
	orphan   bool // continuation of a cursor the proxy never saw issued
	poisoned bool // a page was refused; no completion verdict can follow
	complete bool

	seenCursors map[string]bool
	names       map[string]bool
	tools       []surfacelock.Tool // Name+HTool only, for the completion rollup
	bytes       int
	pages       int
}

// verdict is the outcome of verifying one frame.
type verdict struct {
	refuse   bool
	code     int    // JSON-RPC error code when refuse
	msg      string // client-facing refusal message (bounded, sanitized)
	findings []string

	drift        bool // outcome flags for the session exit code
	inadmissible bool
}

func forwardVerdict(findings ...string) verdict { return verdict{findings: findings} }

func newVerifier(entry *surfacelock.ServerLock, name string, warn bool, lim surfacelock.Limits) *verifier {
	v := &verifier{entry: entry, name: name, warn: warn, lim: lim,
		lockTools: make(map[string]*surfacelock.ToolLock, len(entry.Tools))}
	for i := range entry.Tools {
		v.lockTools[entry.Tools[i].Name] = &entry.Tools[i]
	}
	return v
}

func (v *verifier) newEnumeration(era string, orphan bool) *enumeration {
	v.nextEnumID++
	return &enumeration{id: v.nextEnumID, era: era, orphan: orphan,
		seenCursors: map[string]bool{}, names: map[string]bool{}}
}

// inadmissibleVerdict refuses a frame no verdict can be built on. Distinct from
// drift in code, wording, and remedy: an inadmissible surface is the server
// serving hostile or broken bytes, not a changed surface.
func (v *verifier) inadmissibleVerdict(what string, err error) verdict {
	detail := boundText(err.Error(), 300)
	return verdict{
		refuse:       true,
		code:         codeInadmissibleRefused,
		msg:          fmt.Sprintf("surfacelock[%s]: INADMISSIBLE %s: %s — refusing to forward; no drift verdict is possible on these bytes", v.name, what, detail),
		findings:     []string{fmt.Sprintf("INADMISSIBLE REFUSED (%s): %s — not forwarded", what, detail)},
		inadmissible: true,
	}
}

// toolDrift is one drifted tool on a page.
type toolDrift struct {
	name    string
	classes []surfacelock.Class
}

func (d toolDrift) hasNewPromptText() bool {
	for _, c := range d.classes {
		if c == surfacelock.ClassDescription || c == surfacelock.ClassAdded {
			return true
		}
	}
	return false
}

// resolveDrift turns observed drift into a verdict under the policy:
// strict (default) refuses everything; --warn forwards with a warning EXCEPT
// drift that introduces unreviewed prompt text (description changes, server
// instructions changes, added tools), which refuses even there — the injection
// vector never rides the escape hatch.
func (v *verifier) resolveDrift(what string, drifts []toolDrift, instructionsChanged, flowMismatch bool, eraDrift string) verdict {
	newPrompt := instructionsChanged
	classSet := map[string]bool{}
	if instructionsChanged {
		classSet["description"] = true
	}
	if flowMismatch {
		classSet["flow"] = true
	}
	if eraDrift != "" {
		classSet["era"] = true
	}
	var toolBits []string
	for i, d := range drifts {
		if d.hasNewPromptText() {
			newPrompt = true
		}
		names := make([]string, 0, len(d.classes))
		for _, c := range d.classes {
			classSet[c.String()] = true
			names = append(names, c.String())
		}
		if i < 3 {
			toolBits = append(toolBits, fmt.Sprintf("tool %.64q [%s]", d.name, strings.Join(names, "+")))
		}
	}
	if len(drifts) > 3 {
		toolBits = append(toolBits, fmt.Sprintf("+%d more", len(drifts)-3))
	}
	classes := make([]string, 0, len(classSet))
	for c := range classSet {
		classes = append(classes, c)
	}
	sort.Strings(classes)

	var detailParts []string
	if instructionsChanged {
		detailParts = append(detailParts, "server instructions changed")
	}
	if flowMismatch {
		detailParts = append(detailParts, "negotiation flow differs from the recorded protocol.flow")
	}
	if eraDrift != "" {
		detailParts = append(detailParts, eraDrift)
	}
	detailParts = append(detailParts, toolBits...)
	detail := strings.Join(detailParts, "; ")

	phase := "connect-time"
	if v.everClean {
		phase = "MID-SESSION"
	}
	label := fmt.Sprintf("[%s] %s", strings.Join(classes, "+"), what)

	if v.warn && !newPrompt {
		return verdict{
			drift: true,
			findings: []string{fmt.Sprintf("DRIFT WARNED (%s) %s: %s — forwarded (--warn)",
				phase, label, detail)},
		}
	}
	msg := fmt.Sprintf("surfacelock[%s]: DRIFT REFUSED %s: %s — the pinned tool surface changed; review the upstream change, then accept it explicitly: surfacelock pin --name %q", v.name, label, detail, v.name)
	finding := fmt.Sprintf("DRIFT REFUSED (%s) %s: %s — not forwarded; review then: surfacelock pin --name %q", phase, label, detail, v.name)
	if v.warn && newPrompt {
		msg += " (--warn does not forward new prompt text)"
		finding += " (--warn does not forward new prompt text)"
	}
	return verdict{refuse: true, code: codeDriftRefused, msg: msg, drift: true,
		findings: []string{finding}}
}

// verifyHandshake verifies a surface-bearing handshake result — classic
// `initialize` or stateless `server/discover` — against the locked entry: flow,
// era, and instructions (prompt text; description severity).
func (v *verifier) verifyHandshake(flowObserved string, result json.RawMessage, reqEra string) verdict {
	lock := v.entry
	var era string
	var instrRaw json.RawMessage

	switch flowObserved {
	case surfacelock.FlowClassic:
		obj, err := surfacelock.DecodeExact(result, "initialize result", "protocolVersion", "instructions", "serverInfo")
		if err != nil {
			return v.inadmissibleVerdict("initialize result", err)
		}
		if err := json.Unmarshal(obj["protocolVersion"], &era); err != nil || era == "" {
			return v.inadmissibleVerdict("initialize result",
				fmt.Errorf("no protocolVersion string — the surface cannot be era-tagged"))
		}
		if err := surfacelock.CheckEra(era); err != nil {
			return v.inadmissibleVerdict("initialize result", err)
		}
		instrRaw = obj["instructions"]
	case surfacelock.FlowStateless:
		obj, err := surfacelock.DecodeExact(result, "server/discover result", "supportedVersions", "instructions", "serverInfo")
		if err != nil {
			return v.inadmissibleVerdict("server/discover result", err)
		}
		era = reqEra // stateless: each request names the dialect it speaks
		var supported []string
		if raw, ok := obj["supportedVersions"]; ok {
			if err := json.Unmarshal(raw, &supported); err != nil {
				return v.inadmissibleVerdict("server/discover result",
					fmt.Errorf("supportedVersions is not a string array"))
			}
		}
		var supportedOK bool
		for _, s := range supported {
			if s == era {
				supportedOK = true
			}
		}
		if !supportedOK {
			return v.resolveDrift("server/discover", nil, false, false,
				fmt.Sprintf("supportedVersions no longer includes the session era %q", era))
		}
		instrRaw = obj["instructions"]
	default:
		return v.inadmissibleVerdict("handshake", fmt.Errorf("unknown flow %q", flowObserved))
	}

	flowMismatch := lock.Protocol.Flow != "" && lock.Protocol.Flow != flowObserved
	eraDrift := ""
	if era != lock.Protocol.Era {
		eraDrift = fmt.Sprintf("session era %q, locked era %q (lock with --offer matching this client, or re-pin)", era, lock.Protocol.Era)
	}

	// Instructions ride Admit so the hostile-input rules (raw-byte UTF-8, string
	// type, size cap, canonicalizability) are the same ones lock/verify apply.
	adm, err := surfacelock.Admit(surfacelock.RawSurface{Offered: era, Era: era, Instructions: instrRaw}, v.lim)
	if err != nil {
		return v.inadmissibleVerdict("handshake instructions", err)
	}
	instructionsChanged := adm.HInstr != lock.HInstr

	if flowMismatch || eraDrift != "" || instructionsChanged {
		vd := v.resolveDrift(flowObserved+" handshake", nil, instructionsChanged, flowMismatch, eraDrift)
		if !vd.refuse {
			// Warn-forwarded handshake: the session proceeds under the observed
			// era so later pages verify against what is actually being spoken.
			v.handshakeEra = era
		}
		return vd
	}
	v.handshakeEra = era
	return forwardVerdict(fmt.Sprintf("verified %s handshake: era %s, instructions match (h=%s)",
		flowObserved, era, shortHash(lock.HInstr)))
}

// verifyToolsPage verifies one tools/list result page within its enumeration and
// returns the verdict plus the page's nextCursor ("" when the enumeration is
// complete). The caller forwards or refuses based on the verdict and registers
// the cursor only on forward.
func (v *verifier) verifyToolsPage(en *enumeration, result json.RawMessage) (verdict, string) {
	en.pages++
	if en.pages > v.lim.MaxPages {
		en.poisoned = true
		return v.inadmissibleVerdict("tools/list", fmt.Errorf("more than %d pages", v.lim.MaxPages)), ""
	}
	adm, err := surfacelock.Admit(surfacelock.RawSurface{Offered: en.era, Era: en.era,
		Pages: []json.RawMessage{result}}, v.lim)
	if err != nil {
		en.poisoned = true
		return v.inadmissibleVerdict("tools/list page", err), ""
	}

	// Cross-page rules Admit cannot see from a single page: duplicates across the
	// enumeration and the whole-enumeration caps.
	var drifts []toolDrift
	for i := range adm.Tools {
		t := &adm.Tools[i]
		if en.names[t.Name] {
			en.poisoned = true
			return v.inadmissibleVerdict("tools/list page",
				fmt.Errorf("duplicate tool name %q across pages", t.Name)), ""
		}
		en.names[t.Name] = true
		en.bytes += len(t.Canon)
		if en.bytes > v.lim.MaxSurfaceBytes {
			en.poisoned = true
			return v.inadmissibleVerdict("tools/list page",
				fmt.Errorf("surface exceeds %d canonical bytes", v.lim.MaxSurfaceBytes)), ""
		}
		if len(en.names) > v.lim.MaxTools {
			en.poisoned = true
			return v.inadmissibleVerdict("tools/list page",
				fmt.Errorf("more than %d tools", v.lim.MaxTools)), ""
		}
		en.tools = append(en.tools, surfacelock.Tool{Name: t.Name, HTool: t.HTool})

		lt, ok := v.lockTools[t.Name]
		if !ok {
			drifts = append(drifts, toolDrift{name: t.Name, classes: []surfacelock.Class{surfacelock.ClassAdded}})
			continue
		}
		if lt.HTool != t.HTool {
			classes, cerr := surfacelock.ClassifyTool(lt.Tool, t.Canon)
			if cerr != nil {
				en.poisoned = true
				return v.inadmissibleVerdict("tools/list page",
					fmt.Errorf("tool %q cannot be classified: %v", t.Name, cerr)), ""
			}
			drifts = append(drifts, toolDrift{name: t.Name, classes: classes})
		}
	}

	next, err := pageNextCursor(result)
	if err != nil {
		en.poisoned = true
		return v.inadmissibleVerdict("tools/list page", err), ""
	}
	if next != "" {
		if len(next) > v.lim.MaxCursorBytes {
			en.poisoned = true
			return v.inadmissibleVerdict("tools/list page",
				fmt.Errorf("cursor exceeds %d bytes", v.lim.MaxCursorBytes)), ""
		}
		if en.seenCursors[next] {
			en.poisoned = true
			return v.inadmissibleVerdict("tools/list page",
				fmt.Errorf("cursor loop (cursor repeated)")), ""
		}
		en.seenCursors[next] = true
	}
	complete := next == ""

	if complete && !en.orphan {
		for name := range v.lockTools {
			if !en.names[name] {
				drifts = append(drifts, toolDrift{name: name, classes: []surfacelock.Class{surfacelock.ClassRemoved}})
			}
		}
	}

	if len(drifts) > 0 {
		vd := v.resolveDrift("tools/list", drifts, false, false, "")
		if vd.refuse {
			en.poisoned = true
			return vd, ""
		}
		// Warn-forwarded drift: the enumeration keeps going but can never earn a
		// clean completion claim.
		if complete {
			en.complete = true
			vd.findings = append(vd.findings, fmt.Sprintf(
				"tools/list complete under --warn: %d tools, era %s — no clean-surface claim", len(en.names), en.era))
		}
		return vd, next
	}

	if !complete {
		return forwardVerdict(), next
	}
	en.complete = true
	if en.orphan {
		return forwardVerdict(fmt.Sprintf(
			"verified partial tools/list (unknown cursor): %d tools, per-tool verdicts only — no completeness claim", len(en.names))), ""
	}

	// Everything individually verified equal; the rollup is the belt-and-braces
	// restatement, and it must agree — a clean claim over disagreeing hashes is
	// the classifier-says-clean failure mode.
	rollup := &surfacelock.Surface{Era: en.era, HInstr: v.entry.HInstr, Tools: en.tools}
	hash, err := rollup.SurfaceHash()
	if err != nil {
		return v.inadmissibleVerdict("tools/list rollup", err), ""
	}
	if en.era == v.entry.Protocol.Era && hash != v.entry.SurfaceHash {
		en.poisoned = true
		return v.inadmissibleVerdict("tools/list rollup",
			fmt.Errorf("recomputed surface_hash disagrees with the lock despite per-tool matches")), ""
	}
	v.everClean = true
	return forwardVerdict(fmt.Sprintf("verified tools/list complete: %d tools, era %s, %s (matches lock)",
		len(en.names), en.era, hash)), ""
}

// pageNextCursor reads the page's nextCursor with exact keys. Admit has already
// refused case-variant aliases of "nextCursor" on this page.
func pageNextCursor(result json.RawMessage) (string, error) {
	var page map[string]json.RawMessage
	if err := json.Unmarshal(result, &page); err != nil {
		return "", fmt.Errorf("page does not parse: %v", err)
	}
	raw, ok := page["nextCursor"]
	if !ok || isJSONNull(raw) {
		return "", nil
	}
	var next string
	if err := json.Unmarshal(raw, &next); err != nil {
		return "", fmt.Errorf("nextCursor is not a string")
	}
	return next, nil
}

func shortHash(h string) string {
	if len(h) > 19 {
		return h[:19] + "…"
	}
	return h
}

// boundText bounds and sanitizes text that may carry attacker-influenced bytes
// before it reaches a refusal message or a finding line.
func boundText(s string, max int) string {
	s = surfacelock.Sanitize(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
