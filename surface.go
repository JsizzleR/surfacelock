package surfacelock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrInadmissible marks a surface no verdict can be built on (SPEC.md §6).
// Inadmissibility is distinct from drift: an inadmissible surface never produces a
// lockfile and never produces a drift verdict.
var ErrInadmissible = errors.New("inadmissible surface")

func inadmissible(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInadmissible, fmt.Sprintf(format, args...))
}

// nameCapBytes and eraCapBytes are FIXED by the format (SPEC.md §6), not tunable:
// they bound identifiers that are map keys, sort keys, and terminal output, so a
// second implementation must use the same values or admit surfaces this one refuses.
const (
	nameCapBytes = 128
	eraCapBytes  = 64
)

// Limits are the tunable SPEC.md §6 admissibility caps. They are required to exist;
// the zero value is not usable — start from DefaultLimits. The name and era caps are
// NOT here: they are format constants (nameCapBytes, eraCapBytes).
type Limits struct {
	MaxPageBytes         int // per tools/list page body (also enforced by the fetcher)
	MaxPages             int // fully-paginated fetch page cap
	MaxCursorBytes       int // nextCursor size cap
	MaxToolBytes         int // per-tool canonical bytes
	MaxSurfaceBytes      int // total canonical surface bytes
	MaxTools             int // tool count cap
	MaxInstructionsBytes int // server instructions cap
}

// DefaultLimits are the reference caps documented in SPEC.md §6.
func DefaultLimits() Limits {
	return Limits{
		MaxPageBytes:         4 << 20,
		MaxPages:             100,
		MaxCursorBytes:       4096,
		MaxToolBytes:         1 << 20,
		MaxSurfaceBytes:      16 << 20,
		MaxTools:             10000,
		MaxInstructionsBytes: 64 << 10,
	}
}

// Tool is one admitted tool: its canonical bytes and the three hashes.
type Tool struct {
	Name    string
	Canon   []byte // RFC 8785 form of the entire tool object as served
	HTool   string
	HSchema string // AbsentSentinel if the tool has no inputSchema
	HDesc   string // AbsentSentinel if the tool has no description
}

// Surface is an admitted tool surface: era-tagged, name-sorted, hostile input
// already refused.
type Surface struct {
	Offered      string
	Era          string
	Flow         string  // fetch flow the bytes were taken over ("stateless" | "classic"); "" when unknown (e.g. re-hashed from a stored entry that predates the field)
	Instructions *string // nil = absent
	HInstr       string  // AbsentSentinel when Instructions is nil
	Tools        []Tool  // sorted ascending by byte-wise order of Name
	ServerInfo   *ServerInfo
}

// RawSurface is what a fetcher hands to Admit: the era negotiation outcome and the
// verbatim tools/list pages. Nothing in it has been validated yet.
type RawSurface struct {
	Offered      string
	Era          string
	Flow         string          // "stateless" | "classic" | "" — set by the fetcher, recorded (never hashed)
	Instructions json.RawMessage // raw JSON value; nil if the field was absent
	ServerInfo   json.RawMessage // raw serverInfo value; nil if absent; informational
	Pages        []json.RawMessage
}

// CheckEra validates a negotiated protocol revision against SPEC.md §6 name rules
// (non-empty, ≤64 bytes, valid UTF-8, no control characters). It is exported so the
// fetcher can refuse a hostile era BEFORE using it as an HTTP header value or as the
// rollup preimage, rather than letting the failure surface later as a transport
// error. The returned error wraps ErrInadmissible.
func CheckEra(era string) error {
	if err := validName(era, eraCapBytes); err != nil {
		return inadmissible("negotiated protocolVersion %s", err)
	}
	return nil
}

// Admit validates a raw fetch result against SPEC.md §6 and returns the admitted
// surface. Every returned error wraps ErrInadmissible unless it is a programmer error.
func Admit(raw RawSurface, lim Limits) (*Surface, error) {
	if err := CheckEra(raw.Era); err != nil {
		return nil, err
	}
	if raw.Flow != "" && raw.Flow != "stateless" && raw.Flow != "classic" {
		return nil, inadmissible("unknown fetch flow %.32q", raw.Flow)
	}
	s := &Surface{Offered: raw.Offered, Era: raw.Era, Flow: raw.Flow, HInstr: AbsentSentinel}

	if raw.Instructions != nil && !isNull(raw.Instructions) {
		// Validity is checked on the RAW token: after json.Unmarshal, invalid UTF-8
		// has already been replaced with U+FFFD, so a decoded-string check is vacuous
		// against the wire (and JCS passes invalid bytes through verbatim).
		if !utf8.Valid(raw.Instructions) {
			return nil, inadmissible("instructions are not valid UTF-8")
		}
		var instr string
		if err := json.Unmarshal(raw.Instructions, &instr); err != nil {
			return nil, inadmissible("instructions is not a string")
		}
		if len(instr) > lim.MaxInstructionsBytes {
			return nil, inadmissible("instructions exceed %d bytes", lim.MaxInstructionsBytes)
		}
		h, err := HashCanonical(raw.Instructions)
		if err != nil {
			return nil, inadmissible("instructions: %v", err)
		}
		s.Instructions = &instr
		s.HInstr = h
	}

	s.ServerInfo = sanitizeServerInfo(raw.ServerInfo)

	// Admit enforces its own caps: RawSurface is a documented seam (a library caller
	// can feed captured pages without going through the fetcher), so admission cannot
	// rely on the transport having bounded the input.
	if len(raw.Pages) > lim.MaxPages {
		return nil, inadmissible("more than %d pages", lim.MaxPages)
	}
	seen := map[string]bool{}
	totalBytes := 0
	for pi, page := range raw.Pages {
		if len(page) > lim.MaxPageBytes {
			return nil, inadmissible("page %d exceeds %d bytes", pi+1, lim.MaxPageBytes)
		}
		// Raw-byte UTF-8 check: JCS passes invalid UTF-8 through verbatim, so
		// without this a hostile page would put non-UTF-8 bytes into the lockfile
		// (against §3) and let drift hide behind U+FFFD-collapsed comparisons.
		if !utf8.Valid(page) {
			return nil, inadmissible("page %d is not valid UTF-8", pi+1)
		}
		// Canonicalizing the whole page catches duplicate top-level keys (e.g. a
		// second byte-identical "tools" member that a last-key-wins decoder would
		// silently prefer) — a page-envelope aliasing attack the per-tool checks
		// cannot see.
		if _, err := Canonicalize(page); err != nil {
			return nil, inadmissible("page %d is not canonicalizable: %v", pi+1, err)
		}
		// Decode into a map (exact, case-sensitive keys), NOT a struct: json.Unmarshal
		// matches struct fields case-INsensitively, so `{"tools":[safe],"TOOLS":[bad]}`
		// — distinct keys to JCS, so it passes canonicalization — would last-key-win
		// into a struct's Tools field. Reject any case-variant of "tools" and read the
		// exact key.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(page, &obj); err != nil {
			return nil, inadmissible("page %d does not parse: %v", pi+1, err)
		}
		for k := range obj {
			if k != "tools" && strings.EqualFold(k, "tools") {
				return nil, inadmissible("page %d has a case-variant of the \"tools\" key: %q", pi+1, k)
			}
			// nextCursor gets the same rule: a case-variant would let a sloppy-decoder
			// client continue an enumeration that an exact-case verifier believed
			// complete, so its completeness verdict would cover a truncated surface.
			if k != "nextCursor" && strings.EqualFold(k, "nextCursor") {
				return nil, inadmissible("page %d has a case-variant of the \"nextCursor\" key: %q", pi+1, k)
			}
		}
		var pageTools []json.RawMessage
		if raw, ok := obj["tools"]; ok && !isNull(raw) {
			if err := json.Unmarshal(raw, &pageTools); err != nil {
				return nil, inadmissible("page %d: tools is not an array", pi+1)
			}
		}
		for _, rawTool := range pageTools {
			// Count check first: bound CPU before decoding/hashing the (N+1)th tool.
			if len(s.Tools) >= lim.MaxTools {
				return nil, inadmissible("more than %d tools", lim.MaxTools)
			}
			tool, err := admitTool(rawTool, lim)
			if err != nil {
				return nil, err
			}
			if seen[tool.Name] {
				return nil, inadmissible("duplicate tool name %q", tool.Name)
			}
			seen[tool.Name] = true
			totalBytes += len(tool.Canon)
			if totalBytes > lim.MaxSurfaceBytes {
				return nil, inadmissible("surface exceeds %d canonical bytes", lim.MaxSurfaceBytes)
			}
			s.Tools = append(s.Tools, *tool)
		}
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Name < s.Tools[j].Name })
	return s, nil
}

// admitTool computes a tool's hashes and enforces the per-tool byte cap. The cap is
// an admission gate (a property of THIS fetch); it is deliberately NOT applied when
// re-hashing stored lockfile content (see hashTool), so that a tool locked under a
// larger cap is never falsely condemned as corrupt (SPEC.md §7 is about
// self-consistency, not size).
func admitTool(rawTool json.RawMessage, lim Limits) (*Tool, error) {
	t, err := hashTool(rawTool)
	if err != nil {
		return nil, err
	}
	if len(t.Canon) > lim.MaxToolBytes {
		return nil, inadmissible("tool %q exceeds %d canonical bytes", t.Name, lim.MaxToolBytes)
	}
	return t, nil
}

// hashTool validates a tool object's shape (UTF-8, object, string name within the
// spec-fixed 128-byte name cap, typed description/inputSchema) and computes h_tool /
// h_desc / h_schema. It applies NO byte caps — those belong to admission.
func hashTool(rawTool json.RawMessage) (*Tool, error) {
	// Raw-byte UTF-8: JCS passes invalid bytes through verbatim, and Validate reaches
	// this function with stored lockfile bytes that never saw Admit's page check.
	if !utf8.Valid(rawTool) {
		return nil, inadmissible("tool is not valid UTF-8")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawTool, &fields); err != nil {
		return nil, inadmissible("tool is not a JSON object: %v", err)
	}
	nameRaw, ok := fields["name"]
	if !ok {
		return nil, inadmissible("tool without a name")
	}
	var name string
	if err := json.Unmarshal(nameRaw, &name); err != nil {
		return nil, inadmissible("tool name is not a string")
	}
	if err := validName(name, nameCapBytes); err != nil {
		return nil, inadmissible("tool name %s", err)
	}

	t := &Tool{Name: name, HSchema: AbsentSentinel, HDesc: AbsentSentinel}
	canon, err := Canonicalize(rawTool)
	if err != nil {
		return nil, inadmissible("tool %q: %v", name, err)
	}
	t.Canon = canon
	t.HTool = hashBytes(canon)

	if r, ok := fields["description"]; ok && !isNull(r) {
		var desc string
		if err := json.Unmarshal(r, &desc); err != nil {
			return nil, inadmissible("tool %q: description is not a string", name)
		}
		if t.HDesc, err = HashCanonical(r); err != nil {
			return nil, inadmissible("tool %q description: %v", name, err)
		}
	}
	if r, ok := fields["inputSchema"]; ok && !isNull(r) {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(r, &obj); err != nil {
			return nil, inadmissible("tool %q: inputSchema is not an object", name)
		}
		if t.HSchema, err = HashCanonical(r); err != nil {
			return nil, inadmissible("tool %q inputSchema: %v", name, err)
		}
	}
	return t, nil
}

// isNull reports whether a raw JSON value is the null literal. A null-valued field
// is treated as absent throughout (SPEC.md §6): a serializer artifact, not content —
// but it still participates in h_tool, which hashes the object verbatim. Only the four
// JSON whitespace characters are trimmed: bytes.TrimSpace would also strip \v and \f,
// which JSON does not consider whitespace, so `\vnull\v` (invalid JSON) must NOT read
// as null.
func isNull(raw json.RawMessage) bool {
	return string(trimJSONSpace(raw)) == "null"
}

func trimJSONSpace(b []byte) []byte {
	return bytes.TrimFunc(b, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// validName enforces SPEC.md §6 name rules: non-empty valid UTF-8, a byte cap, and
// no control characters — names are map keys, sort keys, and terminal output.
func validName(s string, maxBytes int) error {
	if s == "" {
		return errors.New("is empty")
	}
	if len(s) > maxBytes {
		return fmt.Errorf("exceeds %d bytes", maxBytes)
	}
	if !utf8.ValidString(s) {
		return errors.New("is not valid UTF-8")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7F {
			return errors.New("contains control characters")
		}
	}
	return nil
}

// sanitizeServerInfo extracts the informational name/version pair, omitting any
// value that is not a string, not valid UTF-8, or over 256 bytes (SPEC.md §3.1).
// It never refuses: server_info is not part of the surface.
func sanitizeServerInfo(raw json.RawMessage) *ServerInfo {
	if raw == nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	keep := func(key string) string {
		raw, ok := fields[key]
		if !ok {
			return ""
		}
		// UTF-8 validity is checked on the RAW token: json.Unmarshal would replace
		// invalid bytes with U+FFFD, making a decoded-string check vacuous and
		// STORING the mangled text instead of omitting the field (SPEC.md §3.1).
		if !utf8.Valid(raw) {
			return ""
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return ""
		}
		if len(v) > 256 {
			return ""
		}
		return v
	}
	si := &ServerInfo{Name: keep("name"), Version: keep("version")}
	if si.Name == "" && si.Version == "" {
		return nil
	}
	return si
}

// SurfaceHash is the SPEC.md §5 rollup: the hash of the canonical form of an
// era-tagged, name-sorted JSON structure. The preimage is structured JSON, not a
// concatenation — there is no separator a hostile tool name can forge.
func (s *Surface) SurfaceHash() (string, error) {
	type entry struct {
		HTool string `json:"h_tool"`
		Name  string `json:"name"`
	}
	entries := make([]entry, 0, len(s.Tools))
	for _, t := range s.Tools {
		entries = append(entries, entry{HTool: t.HTool, Name: t.Name})
	}
	pre := struct {
		Era    string  `json:"era"`
		HInstr string  `json:"h_instructions"`
		Tools  []entry `json:"tools"`
	}{Era: s.Era, HInstr: s.HInstr, Tools: entries}
	b, err := json.Marshal(pre)
	if err != nil {
		return "", err
	}
	return HashCanonical(b)
}
