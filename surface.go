package surfacelock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// ErrInadmissible marks a surface no verdict can be built on (SPEC.md §6).
// Inadmissibility is distinct from drift: an inadmissible surface never produces a
// lockfile and never produces a drift verdict.
var ErrInadmissible = errors.New("inadmissible surface")

func inadmissible(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInadmissible, fmt.Sprintf(format, args...))
}

// Limits are the SPEC.md §6 admissibility caps. They are required to exist; the
// zero value is not usable — start from DefaultLimits.
type Limits struct {
	MaxPageBytes         int // per tools/list page body (enforced by the fetcher too)
	MaxPages             int // fully-paginated fetch page cap
	MaxCursorBytes       int // nextCursor size cap
	MaxToolBytes         int // per-tool canonical bytes
	MaxSurfaceBytes      int // total canonical surface bytes
	MaxTools             int // tool count cap
	MaxInstructionsBytes int // server instructions cap
	MaxNameBytes         int // tool name cap (SPEC.md fixes 128)
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
		MaxNameBytes:         128,
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
	Instructions json.RawMessage // raw JSON value; nil if the field was absent
	ServerInfo   json.RawMessage // raw serverInfo value; nil if absent; informational
	Pages        []json.RawMessage
}

type toolsListPage struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor json.RawMessage   `json:"nextCursor"`
}

// Admit validates a raw fetch result against SPEC.md §6 and returns the admitted
// surface. Every returned error wraps ErrInadmissible unless it is a programmer error.
func Admit(raw RawSurface, lim Limits) (*Surface, error) {
	if err := validName(raw.Era, 64); err != nil {
		return nil, inadmissible("negotiated protocolVersion %s", err)
	}
	s := &Surface{Offered: raw.Offered, Era: raw.Era, HInstr: AbsentSentinel}

	if raw.Instructions != nil && !isNull(raw.Instructions) {
		var instr string
		if err := json.Unmarshal(raw.Instructions, &instr); err != nil {
			return nil, inadmissible("instructions is not a string")
		}
		if len(instr) > lim.MaxInstructionsBytes {
			return nil, inadmissible("instructions exceed %d bytes", lim.MaxInstructionsBytes)
		}
		if !utf8.ValidString(instr) {
			return nil, inadmissible("instructions are not valid UTF-8")
		}
		h, err := HashCanonical(raw.Instructions)
		if err != nil {
			return nil, inadmissible("instructions: %v", err)
		}
		s.Instructions = &instr
		s.HInstr = h
	}

	s.ServerInfo = sanitizeServerInfo(raw.ServerInfo)

	seen := map[string]bool{}
	totalBytes := 0
	for pi, page := range raw.Pages {
		var p toolsListPage
		if err := json.Unmarshal(page, &p); err != nil {
			return nil, inadmissible("page %d does not parse: %v", pi+1, err)
		}
		for _, rawTool := range p.Tools {
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
			if len(s.Tools) >= lim.MaxTools {
				return nil, inadmissible("more than %d tools", lim.MaxTools)
			}
			s.Tools = append(s.Tools, *tool)
		}
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Name < s.Tools[j].Name })
	return s, nil
}

func admitTool(rawTool json.RawMessage, lim Limits) (*Tool, error) {
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
	if err := validName(name, lim.MaxNameBytes); err != nil {
		return nil, inadmissible("tool name %s", err)
	}

	t := &Tool{Name: name, HSchema: AbsentSentinel, HDesc: AbsentSentinel}
	canon, err := Canonicalize(rawTool)
	if err != nil {
		return nil, inadmissible("tool %q: %v", name, err)
	}
	if len(canon) > lim.MaxToolBytes {
		return nil, inadmissible("tool %q exceeds %d canonical bytes", name, lim.MaxToolBytes)
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
// but it still participates in h_tool, which hashes the object verbatim.
func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
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
		var v string
		if err := json.Unmarshal(fields[key], &v); err != nil {
			return ""
		}
		if len(v) > 256 || !utf8.ValidString(v) {
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
