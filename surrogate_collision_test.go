package surfacelock

import (
	"encoding/json"
	"errors"
	"testing"
)

// A lone surrogate escape followed by any other \u escape has no exact form,
// and the canonicalizer collapses every such pair to U+FFFD: two descriptions
// (or two instructions) a JavaScript or Python client reads differently would
// canonicalize, hash and compare as one, so a description swap would pass
// verify with no drift. SPEC.md §6 refuses lone surrogates anywhere in the
// surface; Admit must refuse them on the raw bytes, not only in the name.
func TestAdmitRefusesLoneSurrogatesOutsideTheName(t *testing.T) {
	lim := DefaultLimits()
	cases := []struct {
		name string
		raw  RawSurface
	}{
		{"description: high then a plain escape", RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","description":"Reads.\ud800\u0041"}`)}},
		{"description: two highs", RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","description":"Reads.\ud800\ud800"}`)}},
		{"description: reversed pair", RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","description":"Reads.\ude00\ud83d"}`)}},
		{"schema property description", RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","inputSchema":{"type":"object","properties":{"p":{"description":"x\ud800\u0041"}}}}`)}},
		{"schema member name", RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","inputSchema":{"type":"object","properties":{"p\ud800\u0041":{}}}}`)}},
		{"page key outside the tools", RawSurface{Era: "e", Pages: []json.RawMessage{json.RawMessage(`{"tools":[{"name":"a"}],"x\ud800\u0041":1}`)}}},
		{"instructions", RawSurface{Era: "e", Instructions: json.RawMessage(`"Use it.\ud800\u0041"`), Pages: pagesOf(`{"name":"a"}`)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Admit(c.raw, lim)
			if !errors.Is(err, ErrInadmissible) {
				h, _ := surfaceHashOrEmpty(s)
				t.Fatalf("admitted (surface hash %s); want ErrInadmissible for a lone surrogate escape", h)
			}
		})
	}
}

// The collision itself, stated as the property the refusal protects: two
// surfaces whose descriptions differ only in their unpaired surrogate escapes
// must not both be admitted under one hash. Measured at v0.2.5: these two
// were, under one surface hash.
func TestAdmitNoHashCollisionAcrossLoneSurrogateForms(t *testing.T) {
	lim := DefaultLimits()
	a, errA := Admit(RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","description":"Reads.\ud800\ud800"}`)}, lim)
	b, errB := Admit(RawSurface{Era: "e", Pages: pagesOf(`{"name":"a","description":"Reads.\ude00\ud83d"}`)}, lim)
	if errA != nil || errB != nil {
		return // refused: no surface, no collision
	}
	ha, _ := a.SurfaceHash()
	hb, _ := b.SurfaceHash()
	if ha == hb {
		t.Fatalf("two different descriptions admitted under one surface hash %s", ha)
	}
}

// Positive control: an escaped, correctly paired surrogate anywhere is admitted.
func TestAdmitAcceptsPairedSurrogateEscapesEverywhere(t *testing.T) {
	raw := RawSurface{Era: "e", Instructions: json.RawMessage(`"I \ud83d\ude00"`),
		Pages: pagesOf(`{"name":"a","description":"D \ud83d\ude00","inputSchema":{"type":"object","properties":{"p\ud83d\ude00":{"description":"\ud83d\ude00"}}}}`)}
	if _, err := Admit(raw, DefaultLimits()); err != nil {
		t.Fatalf("paired surrogate escapes refused: %v", err)
	}
}

func surfaceHashOrEmpty(s *Surface) (string, error) {
	if s == nil {
		return "", nil
	}
	return s.SurfaceHash()
}

// hashTool is what Validate runs on a stored lock's tool bytes, so the refusal
// holds there too, not only in Admit's page check: a lockfile rewritten from
// one lone-surrogate spelling to another would otherwise keep its h_tool.
func TestHashToolRefusesLoneSurrogates(t *testing.T) {
	for _, raw := range []string{
		`{"name":"a","description":"Reads.\ud800\ud800"}`,
		`{"name":"a","description":"Reads.\ude00\ud83d"}`,
		`{"name":"a","inputSchema":{"type":"object","properties":{"p\ud800\u0041":{}}}}`,
	} {
		if _, err := hashTool(json.RawMessage(raw)); !errors.Is(err, ErrInadmissible) {
			t.Errorf("hashTool(%s) = %v, want ErrInadmissible", raw, err)
		}
	}
	if _, err := hashTool(json.RawMessage(`{"name":"a","description":"D \ud83d\ude00"}`)); err != nil {
		t.Errorf("hashTool refused a paired surrogate escape: %v", err)
	}
}
