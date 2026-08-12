package surfacelock

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These literals are computed ONCE, out of band (see testdata/golden.tools.lock),
// and pinned here. They are the interop anchor SPEC.md §10 promises: a second
// implementation of the format must reproduce them byte-for-byte. Asserting against
// them — rather than against the code's own output — is what catches a silent change
// to the hash algorithm, the rollup preimage shape, or the rendering.
const (
	goldenSurfaceHash = "sha256:d0ec5f7d6a9a62800032efdafb75d4398d602b8275a1d966c443d144447990ef"
	goldenAlphaHTool  = "sha256:aa52d14d134d85bdb6df10c62cade3b6d977ef45e3c389955863e15dc32ad4e7"
	goldenBetaHTool   = "sha256:4dbd67e0500e1fba7e574a7ee979c9082f34728f6c9e0a36af24b33b0e275ce9"
	goldenHInstr      = "sha256:fa0046315b5732f619ed150f3685abd9ef5e9f5f3e0ee12bc1d3df1765b22834"
)

// TestGoldenLockfileIsStable pins the exact rendered bytes: Parse then Render of the
// committed golden must reproduce it verbatim. A degenerate Render (no indentation,
// wrong separators, dropped trailing LF) fails here, and so does any change to hash
// values that would make the stored anchors inconsistent.
func TestGoldenLockfileIsStable(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "golden.tools.lock"))
	if err != nil {
		t.Fatal(err)
	}
	lf, err := Parse(want)
	if err != nil {
		t.Fatalf("golden does not parse: %v", err)
	}
	if err := lf.Validate(); err != nil {
		t.Fatalf("golden is not self-consistent: %v", err)
	}
	got, err := lf.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("golden render drift:\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}

	e := lf.Servers["golden"]
	if e.SurfaceHash != goldenSurfaceHash {
		t.Errorf("surface_hash = %s, want pinned %s", e.SurfaceHash, goldenSurfaceHash)
	}
	if e.HInstr != goldenHInstr {
		t.Errorf("h_instructions = %s, want pinned %s", e.HInstr, goldenHInstr)
	}
	if e.Tools[0].HTool != goldenAlphaHTool || e.Tools[1].HTool != goldenBetaHTool {
		t.Errorf("tool h_tool anchors drifted: %s %s", e.Tools[0].HTool, e.Tools[1].HTool)
	}
}

// TestSurfaceHashMatchesIndependentPreimage rebuilds the §5 rollup preimage BY HAND
// from the spec text and hashes it, then asserts SurfaceHash() agrees. This is the
// cross-check that a golden-vs-self-output comparison cannot give: it kills a mutant
// that drops "name" from the preimage, renames a key, or swaps the hash algorithm —
// because the expected value here is derived from the spec, not from the code.
func TestSurfaceHashMatchesIndependentPreimage(t *testing.T) {
	lf, err := loadGolden(t)
	if err != nil {
		t.Fatal(err)
	}
	e := lf.Servers["golden"]

	// SPEC.md §5: JCS of {"era":..,"h_instructions":..,"tools":[{"h_tool":..,"name":..},..sorted by name..]}
	type entry struct {
		HTool string `json:"h_tool"`
		Name  string `json:"name"`
	}
	pre := struct {
		Era    string  `json:"era"`
		HInstr string  `json:"h_instructions"`
		Tools  []entry `json:"tools"`
	}{
		Era:    "2025-11-25",
		HInstr: goldenHInstr,
		Tools: []entry{
			{HTool: goldenAlphaHTool, Name: "alpha"},
			{HTool: goldenBetaHTool, Name: "beta"},
		},
	}
	b, err := json.Marshal(pre)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if want != goldenSurfaceHash {
		t.Fatalf("independent preimage hash %s != pinned golden %s", want, goldenSurfaceHash)
	}
	if e.SurfaceHash != want {
		t.Fatalf("SurfaceHash() %s disagrees with independent preimage %s", e.SurfaceHash, want)
	}
}

func loadGolden(t *testing.T) (*Lockfile, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden.tools.lock"))
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// TestGoldenPreservesHTMLEntities is the cross-representation property in the flesh:
// alpha's description contains < > &, which json.Marshal escapes to < etc and
// JCS then restores. The stored tool bytes must hold the literal characters.
func TestGoldenPreservesHTMLEntities(t *testing.T) {
	lf, err := loadGolden(t)
	if err != nil {
		t.Fatal(err)
	}
	tool := lf.Servers["golden"].Tools[0].Tool
	if !bytes.Contains(tool, []byte("<b>bold</b> & sharp.")) {
		t.Fatalf("HTML entities not stored literally: %s", tool)
	}
}
