package conformance

import (
	"context"
	"fmt"

	"github.com/JsizzleR/surfacelock"
)

// CheckLockEntry validates a lockfile entry's era claim against the live
// server the entry itself names: it probes the entry's transport/target and
// grades the recorded protocol.era. This is the minimal joining piece between
// the tools.lock artifact and the matrix — the era tag stops being a label
// and becomes a checkable claim. The error polarity is ValidateEraClaim's:
// nil only for demonstrated (star-)conformance; an unreachable server FAILS
// the claim rather than passing it silently.
func CheckLockEntry(ctx context.Context, e *surfacelock.ServerLock) (*Report, error) {
	dial, err := DialerForEntry(e)
	if err != nil {
		return nil, err
	}
	rep, err := Check(ctx, e.Target, dial, e.Protocol.Era)
	if err != nil {
		return nil, err
	}
	return rep, ValidateEraClaim(rep)
}

// DialerForEntry builds the Dialer for a lockfile entry's recorded transport.
func DialerForEntry(e *surfacelock.ServerLock) (Dialer, error) {
	switch e.Transport {
	case "http":
		return NewHTTPDialer(e.Target, nil, nil), nil
	case "stdio":
		return NewStdioDialer(append([]string{e.Target}, e.Args...), nil), nil
	default:
		return nil, fmt.Errorf("entry transport %q is not probeable", e.Transport)
	}
}
