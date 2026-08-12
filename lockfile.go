package surfacelock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// ErrLockfile marks a lockfile that is missing, unparseable, invalid, or
// self-inconsistent (SPEC.md §7). Distinct from drift and from inadmissibility.
var ErrLockfile = errors.New("invalid lockfile")

func badLockfile(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLockfile, fmt.Sprintf(format, args...))
}

// LockfileVersion is the format version this package reads and writes.
const LockfileVersion = 1

// Lockfile is the tools.lock document (SPEC.md §3).
type Lockfile struct {
	LockfileVersion int                    `json:"lockfile_version"`
	Servers         map[string]*ServerLock `json:"servers"`
}

// ServerLock is one pinned server entry.
type ServerLock struct {
	Transport    string      `json:"transport"` // "http" | "stdio"
	Target       string      `json:"target"`
	Args         []string    `json:"args"`
	Protocol     Protocol    `json:"protocol"`
	ServerInfo   *ServerInfo `json:"server_info,omitempty"`
	Instructions *string     `json:"instructions,omitempty"`
	HInstr       string      `json:"h_instructions"`
	SurfaceHash  string      `json:"surface_hash"`
	Tools        []ToolLock  `json:"tools"`
}

// Protocol records the offered and negotiated protocol revisions, and the fetch
// flow the lock was taken over. Verifiers re-offer the same value AND re-use the
// recorded flow so negotiation is reproducible (SPEC.md §3.4): without the flow,
// a replacement server speaking only the OTHER flow could serve the locked bytes
// and pass verification while the negotiation path silently changed. The
// negotiated revision is the era. flow is optional for pre-flow lockfiles; a
// verifier falls back to offer-driven selection when it is absent.
type Protocol struct {
	Offered string `json:"offered"`
	Era     string `json:"era"`
	Flow    string `json:"flow,omitempty"` // "stateless" | "classic"
}

// ServerInfo is the informational self-report from initialize. Never hashed, never
// a drift verdict.
type ServerInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// ToolLock is one pinned tool: the canonical object plus its interop hash anchors.
type ToolLock struct {
	Name    string          `json:"name"`
	HDesc   string          `json:"h_desc"`
	HSchema string          `json:"h_schema"`
	HTool   string          `json:"h_tool"`
	Tool    json.RawMessage `json:"tool"`
}

// NewLockfile returns an empty version-1 lockfile.
func NewLockfile() *Lockfile {
	return &Lockfile{LockfileVersion: LockfileVersion, Servers: map[string]*ServerLock{}}
}

// EntryFromSurface builds a server entry from an admitted surface.
func EntryFromSurface(transport, target string, args []string, s *Surface) (*ServerLock, error) {
	hash, err := s.SurfaceHash()
	if err != nil {
		return nil, err
	}
	if args == nil {
		args = []string{}
	}
	e := &ServerLock{
		Transport:    transport,
		Target:       target,
		Args:         args,
		Protocol:     Protocol{Offered: s.Offered, Era: s.Era, Flow: s.Flow},
		ServerInfo:   s.ServerInfo,
		Instructions: s.Instructions,
		HInstr:       s.HInstr,
		SurfaceHash:  hash,
		Tools:        make([]ToolLock, 0, len(s.Tools)),
	}
	for _, t := range s.Tools {
		e.Tools = append(e.Tools, ToolLock{
			Name: t.Name, HDesc: t.HDesc, HSchema: t.HSchema, HTool: t.HTool,
			Tool: json.RawMessage(t.Canon),
		})
	}
	return e, nil
}

// Render produces the canonical file bytes (SPEC.md §4): RFC 8785 over the whole
// document, re-indented with two spaces, one trailing LF. The same surface renders
// byte-identically on every machine, every time.
func (lf *Lockfile) Render() ([]byte, error) {
	b, err := json.Marshal(lf)
	if err != nil {
		return nil, err
	}
	canon, err := Canonicalize(b)
	if err != nil {
		return nil, err
	}
	return renderIndented(canon)
}

var hashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validHash(h string, absentOK bool) bool {
	if h == AbsentSentinel {
		return absentOK
	}
	return hashRe.MatchString(h)
}

// Parse reads and structurally validates a lockfile (SPEC.md §7). Unknown fields are
// rejected: lockfile_version is the extension mechanism, and tolerant readers create
// silent forks of the format. Parse does NOT verify hash self-consistency — that is
// Validate, which costs a canonicalization pass per tool.
func Parse(b []byte) (*Lockfile, error) {
	// SPEC.md §3: the artifact is UTF-8. Enforce it on the raw bytes — JSON decoding
	// would silently replace invalid sequences with U+FFFD inside RawMessage-held
	// tool objects, and a later re-render would launder the corruption into a fresh
	// canonical file.
	if !utf8.Valid(b) {
		return nil, badLockfile("file is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var lf Lockfile
	if err := dec.Decode(&lf); err != nil {
		return nil, badLockfile("%v", err)
	}
	// A second document after the first is not a lockfile.
	if dec.More() {
		return nil, badLockfile("trailing content after the document")
	}
	if lf.LockfileVersion != LockfileVersion {
		return nil, badLockfile("lockfile_version %d is not %d", lf.LockfileVersion, LockfileVersion)
	}
	if lf.Servers == nil {
		return nil, badLockfile("missing servers")
	}
	for name, e := range lf.Servers {
		if err := e.validateShape(); err != nil {
			return nil, badLockfile("server %q: %v", name, err)
		}
	}
	return &lf, nil
}

func (e *ServerLock) validateShape() error {
	if e == nil {
		return errors.New("null entry")
	}
	switch e.Transport {
	case "http", "stdio":
	default:
		return fmt.Errorf("unknown transport %q", e.Transport)
	}
	if e.Target == "" {
		return errors.New("missing target")
	}
	if e.Args == nil {
		return errors.New("missing args")
	}
	if e.Transport == "http" && len(e.Args) > 0 {
		return errors.New("args must be empty for http")
	}
	if e.Protocol.Offered == "" || e.Protocol.Era == "" {
		return errors.New("missing protocol.offered or protocol.era")
	}
	// The era is bound into the rollup and printed to the terminal; a hand-crafted
	// lockfile must not smuggle control characters through the read path (the fetch
	// path validates it via CheckEra).
	if err := validName(e.Protocol.Era, eraCapBytes); err != nil {
		return fmt.Errorf("protocol.era %v", err)
	}
	if f := e.Protocol.Flow; f != "" && f != "stateless" && f != "classic" {
		return fmt.Errorf("protocol.flow %.32q is not \"stateless\" or \"classic\"", f)
	}
	if err := validName(e.Protocol.Offered, eraCapBytes); err != nil {
		return fmt.Errorf("protocol.offered %v", err)
	}
	if !validHash(e.HInstr, true) {
		return fmt.Errorf("bad h_instructions %q", e.HInstr)
	}
	if (e.Instructions != nil) != (e.HInstr != AbsentSentinel) {
		return errors.New("instructions and h_instructions disagree about absence")
	}
	if !validHash(e.SurfaceHash, false) {
		return fmt.Errorf("bad surface_hash %q", e.SurfaceHash)
	}
	if e.Tools == nil {
		return errors.New("missing tools")
	}
	prev := ""
	for i, t := range e.Tools {
		if err := validName(t.Name, nameCapBytes); err != nil {
			return fmt.Errorf("tool %d: name %v", i, err)
		}
		if i > 0 && t.Name <= prev {
			return fmt.Errorf("tools not sorted strictly by name at %q", t.Name)
		}
		prev = t.Name
		if !validHash(t.HDesc, true) || !validHash(t.HSchema, true) || !validHash(t.HTool, false) {
			return fmt.Errorf("tool %q: malformed hash", t.Name)
		}
		if len(t.Tool) == 0 {
			return fmt.Errorf("tool %q: missing tool object", t.Name)
		}
	}
	return nil
}

// Validate checks the self-consistency of every entry (SPEC.md §7). A reader MUST
// reject a self-inconsistent lockfile, so every verb that reads one calls this before
// trusting it — otherwise lock/pin could re-render a corrupt sibling entry and verify
// could pass a clean entry while a tampered one sits beside it.
func (lf *Lockfile) Validate() error {
	for name, e := range lf.Servers {
		if err := e.Validate(); err != nil {
			return badLockfile("server %q: %v", name, err)
		}
	}
	return nil
}

// Validate checks hash self-consistency (SPEC.md §7): every stored hash must equal
// the value recomputed from the stored content. A lockfile whose hashes disagree with
// its own content has been corrupted or tampered with; comparing a live surface
// against it would produce a confident verdict about nothing.
func (e *ServerLock) Validate() error {
	if e.Instructions != nil {
		b, err := json.Marshal(*e.Instructions)
		if err != nil {
			return badLockfile("instructions: %v", err)
		}
		h, err := HashCanonical(b)
		if err != nil {
			return badLockfile("instructions: %v", err)
		}
		if h != e.HInstr {
			return badLockfile("h_instructions does not match stored instructions")
		}
	}
	entries := make([]Tool, 0, len(e.Tools))
	for _, t := range e.Tools {
		// hashTool, NOT admitTool: self-consistency is about the stored hashes
		// matching the stored content, never about size caps. A tool locked under a
		// larger MaxToolBytes must not be condemned as corrupt here (SPEC.md §7).
		got, err := hashTool(t.Tool)
		if err != nil {
			return badLockfile("tool %q: stored object: %v", t.Name, err)
		}
		if got.Name != t.Name {
			return badLockfile("tool %q: stored object is named %q", t.Name, got.Name)
		}
		if got.HTool != t.HTool || got.HSchema != t.HSchema || got.HDesc != t.HDesc {
			return badLockfile("tool %q: stored hashes do not match stored object", t.Name)
		}
		entries = append(entries, *got)
	}
	s := &Surface{Era: e.Protocol.Era, HInstr: e.HInstr, Tools: entries}
	hash, err := s.SurfaceHash()
	if err != nil {
		return badLockfile("surface_hash: %v", err)
	}
	if hash != e.SurfaceHash {
		return badLockfile("surface_hash does not match stored content")
	}
	return nil
}
