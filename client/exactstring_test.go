package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JsizzleR/surfacelock"
)

// classicPagesServer serves classic initialize at era (a raw JSON token) and
// tools/list pages: the first carries nextCursor (a raw JSON token, "" for
// none); a continuation is answered with a last page and its cursor recorded.
func classicPagesServer(t *testing.T, era, nextCursor string, sawCursor *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor json.RawMessage `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/json")
		switch in.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%s}}`, in.ID, era)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if in.Params.Cursor == nil {
				nc := ""
				if nextCursor != "" {
					nc = `,"nextCursor":` + nextCursor
				}
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"a"}]%s}}`, in.ID, nc)
				return
			}
			*sawCursor = string(in.Params.Cursor)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"b"}]}}`, in.ID)
		}
	}))
}

// A nextCursor with no exact string form is refused: the client would send
// back a cursor the server never issued (U+FFFD for the lone half) and key
// its loop check on a value two different cursors share.
func TestFetchCursorReadExactly(t *testing.T) {
	for _, cursor := range []string{`"p2\ud800"`, `"p2\udc00"`, `"p2\ud800\ud800"`, `"p2\ude00\ud83d"`, "\"p2\xff\""} {
		t.Run(cursor, func(t *testing.T) {
			var saw string
			srv := classicPagesServer(t, `"2025-11-25"`, cursor, &saw)
			defer srv.Close()
			_, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL, Offered: "2025-11-25"}, surfacelock.DefaultLimits())
			if !errors.Is(err, surfacelock.ErrInadmissible) {
				t.Fatalf("Fetch: %v (continuation sent %s), want ErrInadmissible", err, saw)
			}
		})
	}
	// Controls: the same cursor as raw UTF-8 and as an escaped, paired surrogate
	// (JSON escapes, not Go ones: the wire carries the backslashes) continues.
	for _, cursor := range []string{`"p2😀"`, `"p2\ud83d\ude00"`, `"p2\uD83D\uDE00"`} {
		t.Run("paired control "+cursor, func(t *testing.T) {
			var saw string
			srv := classicPagesServer(t, `"2025-11-25"`, cursor, &saw)
			defer srv.Close()
			raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL, Offered: "2025-11-25"}, surfacelock.DefaultLimits())
			if err != nil || len(raw.Pages) != 2 {
				t.Fatalf("Fetch: %v, want two pages", err)
			}
			var got string
			if json.Unmarshal([]byte(saw), &got) != nil || got != "p2\U0001F600" {
				t.Errorf("continuation cursor %s, want the issued one", saw)
			}
		})
	}
	// A null nextCursor ends the enumeration, as an absent one does: it is not
	// a non-string cursor.
	t.Run("null ends pagination", func(t *testing.T) {
		var saw string
		srv := classicPagesServer(t, `"2025-11-25"`, `null`, &saw)
		defer srv.Close()
		raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL, Offered: "2025-11-25"}, surfacelock.DefaultLimits())
		if err != nil || len(raw.Pages) != 1 || saw != "" {
			t.Fatalf("Fetch: %v (continuation %q), want one page and no continuation", err, saw)
		}
	})
}

// The negotiated era is recorded in the lock and hashed; one with no exact
// string form would record U+FFFD for a value the server did not send.
func TestFetchClassicEraReadExactly(t *testing.T) {
	var saw string
	srv := classicPagesServer(t, `"2025-11-25\udc00\udc00"`, "", &saw)
	defer srv.Close()
	raw, err := Fetch(context.Background(), Ref{Transport: "http", Target: srv.URL, Offered: "2025-11-25"}, surfacelock.DefaultLimits())
	if err == nil {
		t.Fatalf("Fetch locked era %q, want a refusal", raw.Era)
	}
	if !errors.Is(err, surfacelock.ErrInadmissible) {
		t.Errorf("Fetch: %v, want ErrInadmissible (as a control-char era is)", err)
	}
}
