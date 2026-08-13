package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// stdioBackend runs the locked stdio server as a child process and relays
// newline-delimited JSON-RPC frames. The child's argv comes from the lockfile
// entry (target + args), its environment from the proxy's own plus Config.Env —
// secrets ride the environment, never the artifact.
type stdioBackend struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	frames chan []byte

	sendMu sync.Mutex
	done   chan struct{} // closed by Close; frees a reader parked on a full frames
	once   sync.Once

	mu     sync.Mutex
	closed bool  // Close started before the reader terminated
	err    error // why the reader terminated, when not caller-initiated
}

func newStdioBackend(target string, args, env []string, childStderr io.Writer) (*stdioBackend, error) {
	cmd := exec.Command(target, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = childStderr // must be drained or a chatty server blocks on a full pipe
	// Its own process group: npx/uvx wrap the real server, and teardown must
	// reach the whole tree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	b := &stdioBackend{cmd: cmd, stdin: stdin,
		frames: make(chan []byte, 64), done: make(chan struct{})}
	go b.readLoop(stdout)
	return b, nil
}

func (b *stdioBackend) readLoop(stdout io.Reader) {
	// readLoop is the SOLE sender to b.frames, so it is the sole closer. Close it
	// on EVERY exit — including the b.done branch — or a consumer ranging Frames()
	// (Run's inbound goroutine) parks forever and Run hangs at teardown's
	// <-inboundDone (measured: a chatty server at disconnect fills the buffer, the
	// select takes the done branch, and the channel is never closed).
	defer close(b.frames)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), relayFrameCap)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		frame := append([]byte(nil), line...)
		select {
		case b.frames <- frame:
		case <-b.done:
			return
		}
	}
	err := sc.Err()
	if err == nil {
		err = errors.New("server closed stdout")
	} else if errors.Is(err, bufio.ErrTooLong) {
		err = fmt.Errorf("server frame exceeds %d bytes", relayFrameCap)
	}
	b.mu.Lock()
	if !b.closed {
		b.err = err // the upstream died on its own; report it
	}
	b.mu.Unlock()
}

func (b *stdioBackend) Send(ctx context.Context, frame []byte) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	// The write runs in a goroutine so a stalled child (full pipe) cannot hold
	// the client-reader loop past ctx; teardown kills the process group, which
	// unblocks the write with EPIPE and lets the goroutine exit.
	done := make(chan error, 1)
	go func() {
		_, err := b.stdin.Write(append(frame, '\n'))
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *stdioBackend) Frames() <-chan []byte { return b.frames }

func (b *stdioBackend) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *stdioBackend) Close() {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		close(b.done)
		b.stdin.Close()
		if b.cmd.Process != nil {
			// Kill the whole group; a second Close must not signal a reused pgid,
			// hence the Once.
			syscall.Kill(-b.cmd.Process.Pid, syscall.SIGKILL)
		}
		b.cmd.Wait()
	})
}
