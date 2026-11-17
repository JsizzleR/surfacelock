package proxy

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/JsizzleR/surfacelock"
)

// ---- cursors and eras are read exactly: a token encoding/json cannot
// represent exactly (an unpaired surrogate escape, invalid UTF-8) decodes to
// U+FFFD, so two different wire values would key as one ----

// A server cursor and a client cursor that differ only in their lone
// surrogate escape decode to one Go string: the proxy would take a cursor the
// upstream never issued for one it did, and count a page it never saw.
func TestCursorAliasingRefused(t *testing.T) {
	entry := entryFor(t, eraClassic, surfacelock.FlowClassic, "", toolA, toolB)

	t.Run("server nextCursor with a lone surrogate escape", func(t *testing.T) {
		h := newHarness(t, entry, false)
		classicHandshake(h, "")
		h.client(listReq(1, ""))
		h.expectUpstream()
		h.inject(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` + toolA + `],"nextCursor":"page2\ud800\ud800"}}`)
		code, msg := errorCodeOf(t, h.expectClient())
		if code != codeInadmissibleRefused {
			t.Fatalf("a page whose nextCursor has no exact string form: code %d (%s), want %d", code, msg, codeInadmissibleRefused)
		}
		// The refusal revokes the session's verified tools.
		expectCallRefused(h, callReq(2, "alpha"), codeCallRefused)
		h.finish()
	})

	for _, tc := range []struct{ name, cursor string }{
		{"client cursor with two high surrogates (JCS accepts it)", `"page2\ud800\ud800"`},
		{"client cursor with two low surrogates (JCS accepts it)", `"page2\udc00\udc00"`},
		{"client cursor with a reversed pair (JCS accepts it)", `"page2\ude00\ud83d"`},
		{"client cursor with a lone half (JCS refuses it)", `"page2\ud800"`},
		{"client cursor with invalid UTF-8", "\"page2\xff\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, entry, false)
			classicHandshake(h, "")
			listClean(h, 1, toolA, toolB)
			h.client(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":` + tc.cursor + `}}`)
			code, msg := errorCodeOf(t, h.expectClient())
			if code != codeInadmissibleRefused {
				t.Fatalf("cursor %s: code %d (%s), want %d", tc.cursor, code, msg, codeInadmissibleRefused)
			}
			expectNotForwarded(h)
			h.finish()
		})
	}

	// The positive control: a paired surrogate escape is an exact string, and
	// the continuation verifies as part of its enumeration.
	// (The wire carries the escapes themselves in the second form, and a client
	// may spell the same cursor either way.)
	for _, c := range []struct{ server, client string }{
		{"page2😀", "page2😀"},
		{`page2\ud83d\ude00`, `page2\ud83d\ude00`},
		{`page2\ud83d\ude00`, "page2😀"},
	} {
		t.Run("paired surrogate cursor control "+c.server+" "+c.client, func(t *testing.T) {
			h := newHarness(t, entry, false)
			classicHandshake(h, "")
			h.client(listReq(1, ""))
			h.expectUpstream()
			h.inject(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` + toolA + `],"nextCursor":"` + c.server + `"}}`)
			if got := h.expectClient(); bytes.Contains(got, []byte(`"error"`)) {
				t.Fatalf("a paired-surrogate nextCursor was refused: %s", got)
			}
			h.client(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"` + c.client + `"}}`)
			h.expectUpstream()
			h.inject(listResult(2, "", toolB))
			if got := h.expectClient(); bytes.Contains(got, []byte(`"error"`)) {
				t.Fatalf("the paired-surrogate continuation was refused: %s", got)
			}
			if out := h.finish(); out.Drift || out.Inadmissible {
				t.Fatalf("a clean two-page enumeration reported %+v", out)
			}
		})
	}
}

// The era a request or a handshake names is compared with the lock's; a token
// with no exact string form is refused before it is compared.
func TestEraTokenReadExactly(t *testing.T) {
	t.Run("classic initialize protocolVersion", func(t *testing.T) {
		entry := entryFor(t, eraClassic, surfacelock.FlowClassic, "", toolA)
		h := newHarness(t, entry, false)
		h.client(initReq(0))
		h.expectUpstream()
		h.inject(`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25\udc00\udc00","capabilities":{},"serverInfo":{"name":"s","version":"1"}}}`)
		code, msg := errorCodeOf(t, h.expectClient())
		if code != codeInadmissibleRefused {
			t.Fatalf("initialize era with a lone surrogate: code %d (%s), want %d", code, msg, codeInadmissibleRefused)
		}
		h.finish()
	})
	t.Run("stateless tools/list _meta protocolVersion", func(t *testing.T) {
		entry := entryFor(t, eraModern, surfacelock.FlowStateless, "", toolA)
		h := newHarness(t, entry, false)
		h.client(fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"%s":"2026-07-28\ud800\ud800"}}}`, metaProtocolVersionKey))
		code, msg := errorCodeOf(t, h.expectClient())
		if code != codeInadmissibleRefused {
			t.Fatalf("tools/list era with a lone surrogate: code %d (%s), want %d", code, msg, codeInadmissibleRefused)
		}
		expectNotForwarded(h)
		h.finish()
	})
	t.Run("server/discover _meta protocolVersion", func(t *testing.T) {
		entry := entryFor(t, eraModern, surfacelock.FlowStateless, "", toolA)
		h := newHarness(t, entry, false)
		h.client(fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"server/discover","params":{"_meta":{"%s":"2026-07-28\ude00\ud83d"}}}`, metaProtocolVersionKey))
		code, msg := errorCodeOf(t, h.expectClient())
		if code != codeProxyRefused {
			t.Fatalf("discover era with a lone surrogate: code %d (%s), want %d", code, msg, codeProxyRefused)
		}
		expectNotForwarded(h)
		h.finish()
	})
}

// A server/discover result whose supportedVersions holds an element with no
// exact string form is refused as inadmissible before any element is compared
// with the era, whichever form the canonicalizer would have passed; a paired
// escape is an exact element.
func TestDiscoverSupportedVersionsReadExactly(t *testing.T) {
	entry := entryFor(t, eraModern, surfacelock.FlowStateless, "", toolA)
	discover := func(h *harness) {
		h.client(fmt.Sprintf(`{"jsonrpc":"2.0","id":"d-1","method":"server/discover","params":{"_meta":{"%s":"%s"}}}`, metaProtocolVersionKey, eraModern))
		h.expectUpstream()
	}
	for _, el := range []string{`"\ud800\ud800"`, `"\ude00\ud83d"`, `"\ud800\u0041"`, "\"\xff\""} {
		t.Run(el, func(t *testing.T) {
			h := newHarness(t, entry, false)
			discover(h)
			h.inject(fmt.Sprintf(`{"jsonrpc":"2.0","id":"d-1","result":{"supportedVersions":["%s",%s],"serverInfo":{"name":"s"}}}`, eraModern, el))
			code, msg := errorCodeOf(t, h.expectClient())
			if code != codeInadmissibleRefused {
				t.Fatalf("element %s: code %d (%s), want %d", el, code, msg, codeInadmissibleRefused)
			}
			h.finish()
		})
	}
	t.Run("paired control", func(t *testing.T) {
		h := newHarness(t, entry, false)
		discover(h)
		h.inject(fmt.Sprintf(`{"jsonrpc":"2.0","id":"d-1","result":{"supportedVersions":["%s","\ud83d\ude00"],"serverInfo":{"name":"s"}}}`, eraModern))
		if got := h.expectClient(); bytes.Contains(got, []byte(`"error"`)) {
			t.Fatalf("a paired-escape element was refused: %s", got)
		}
		h.finish()
	})
}
