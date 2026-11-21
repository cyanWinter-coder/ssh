package ssh

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/anmitsu/go-shlex"
	gossh "golang.org/x/crypto/ssh"
)

// Session provides access to information about an SSH session and methods
// to read and write to the SSH channel with an embedded Channel interface from
// crypto/ssh.
//
// When Command() returns an empty slice, the user requested a shell. Otherwise
// the user is performing an exec with those command arguments.
//
// TODO: Signals.
type Session interface {
	gossh.Channel

	// User returns the username used when establishing the SSH connection.
	User() string

	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr

	// Environ returns a copy of strings representing the environment set by the
	// user for this session, in the form "key=value".
	Environ() []string

	// Exit sends an exit status and then closes the session.
	Exit(code int) error

	// Command returns a shell parsed slice of arguments that were provided by the
	// user. Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	Command() []string

	// RawCommand returns the exact command that was provided by the user.
	RawCommand() string

	// Subsystem returns the subsystem requested by the user.
	Subsystem() string

	// PublicKey returns the PublicKey used to authenticate. If a public key was not
	// used it will return nil.
	PublicKey() PublicKey

	// Context returns the connection's context. The returned context is always
	// non-nil and holds the same data as the Context passed into auth
	// handlers and callbacks.
	//
	// The context is canceled when the client's connection closes or I/O
	// operation fails.
	Context() Context

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers via the Context.
	Permissions() Permissions

	// EmulatedPty returns true if the session is emulating a PTY using PtyWriter.
	EmulatedPty() bool

	// Pty returns PTY information, a channel of window size changes, and a boolean
	// of whether or not a PTY was accepted for this session.
	Pty() (Pty, <-chan Window, bool)

	// Signals registers a channel to receive signals sent from the client. The
	// channel must handle signal sends or it will block the SSH request loop.
	// Registering nil will unregister the channel from signal sends. During the
	// time no channel is registered signals are buffered up to a reasonable amount.
	// If there are buffered signals when a channel is registered, they will be
	// sent in order on the channel immediately after registering.
	Signals(c chan<- Signal)

	// Break regisers a channel to receive notifications of break requests sent
	// from the client. The channel must handle break requests, or it will block
	// the request handling loop. Registering nil will unregister the channel.
	// During the time that no channel is registered, breaks are ignored.
	Break(c chan<- bool)
}

// maxSigBufSize is how many signals will be buffered
// when there is no signal channel specified.
const maxSigBufSize = 128

// DefaultSessionHandler is the default handler for the "session" channel type.
func DefaultSessionHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		slog.Warn("ssh: failed to accept session channel", "err", err)
		return
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           srv.Handler,
		ptyCb:             srv.PtyCallback,
		ptyHandler:        srv.PtyHandler,
		sessReqCb:         srv.SessionRequestCallback,
		subsystemHandlers: srv.SubsystemHandlers,
		ctx:               ctx,
		generation:        contextGeneration(ctx),
		closeChannel:      closeOnce(ch),
	}
	// Register the session before anything can run under it. A session that
	// arrives while the server is draining is refused outright rather than
	// accepted into a set Shutdown no longer waits for.
	if !srv.trackSession(sess, true) {
		_ = sess.closeChannel()
		return
	}
	defer srv.trackSession(sess, false)

	ctx.SetValue(ContextKeySession, sess)
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	gossh.Channel
	conn              *gossh.ServerConn
	handler           Handler
	subsystemHandlers map[string]SubsystemHandler
	handled           bool
	exited            bool
	pty               *Pty
	ptyClose          func() error
	winch             chan Window
	env               []string
	ptyCb             PtyCallback
	ptyHandler        PtyHandler
	sessReqCb         SessionRequestCallback
	rawCmd            string
	subsystem         string
	ctx               Context
	sigCh             chan<- Signal
	sigBuf            []Signal
	breakCh           chan<- bool
	// generation is the connection generation the session was created under.
	// It ties every session to the handshake that admitted it, so diagnostics
	// and ownership checks can tell which connection an event belongs to.
	generation uint64
	// closeChannel closes the underlying channel at most once. The request
	// loop, Exit, and the proxy copy goroutines can all observe the end of a
	// session, so teardown is funnelled through it.
	closeChannel func() error
	// agentRequested is session-scoped: it starts false for every session, so
	// a client cannot inherit an agent request from a previous connection or
	// even a previous session on the same connection.
	agentRequested bool
}

func (sess *session) Stderr() io.ReadWriter {
	if sess.pty != nil && sess.EmulatedPty() {
		return NewPtyReadWriter(sess.Channel.Stderr())
	}
	return sess.Channel.Stderr()
}

func (sess *session) Write(p []byte) (int, error) {
	if sess.pty != nil && sess.EmulatedPty() {
		return NewPtyWriter(sess.Channel).Write(p)
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() PublicKey {
	sessionkey := sess.ctx.Value(ContextKeyPublicKey)
	if sessionkey == nil {
		return nil
	}
	return sessionkey.(PublicKey)
}

func (sess *session) Permissions() Permissions {
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(ContextKeyPermissions).(*Permissions)
	return *perms
}

func (sess *session) Context() Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	if sess.exited {
		sess.Unlock()
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true
	sess.Unlock()

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, gossh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

// Close closes the session's channel exactly once. Callers that race on the
// end of a session (the handler, the request loop, the copy goroutines) all
// funnel here, so repeated closes are idempotent and never report an error for
// an already-released channel.
func (sess *session) Close() error {
	if sess.closeChannel != nil {
		return sess.closeChannel()
	}
	return sess.Channel.Close()
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shlex.Split(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) EmulatedPty() bool {
	return sess.ctx.Value(contextKeyEmulatePty) == true
}

func (sess *session) Pty() (Pty, <-chan Window, bool) {
	sess.Lock()
	defer sess.Unlock()
	if sess.pty != nil && (sess.EmulatedPty() || !sess.pty.IsZero()) {
		return *sess.pty, sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		buf := sess.sigBuf
		sess.sigBuf = nil
		go func() {
			for _, sig := range buf {
				c <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

func (sess *session) handleRequests(reqs <-chan *gossh.Request) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.isHandled() {
				_ = req.Reply(false, nil)
				continue
			}

			payload := struct{ Value string }{}
			_ = gossh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			if sess.handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			sess.setHandled()
			_ = req.Reply(true, nil)

			pty := sess.allocatedPty()
			go func() {
				// Closed from a defer so the pty is still released when the
				// handler panics, rather than trading a crash for a leak. The
				// close is the session's shared once wrapper, so the request
				// loop's own cleanup cannot close it a second time.
				if pty != nil {
					defer func() { _ = sess.closePty() }()
				}
				defer recoverAndLog("panic in session handler", nil, func() {
					_ = sess.Exit(1)
				})
				if pty != nil {
					go func() {
						defer recoverAndLog("panic copying to pty", nil, nil)
						_, _ = io.Copy(pty, sess)
					}()
					go func() {
						defer recoverAndLog("panic copying from pty", nil, nil)
						_, _ = io.Copy(sess, pty)
					}()
				}
				sess.handler(sess)
				_ = sess.Exit(0)
			}()
		case "subsystem":
			if sess.isHandled() {
				_ = req.Reply(false, nil)
				continue
			}

			payload := struct{ Value string }{}
			_ = gossh.Unmarshal(req.Payload, &payload)
			sess.subsystem = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[payload.Value]
			if handler == nil {
				handler = sess.subsystemHandlers["default"]
			}
			if handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			sess.setHandled()
			_ = req.Reply(true, nil)

			go func() {
				defer recoverAndLog("panic in subsystem handler", nil, func() {
					_ = sess.Exit(1)
				})
				handler(sess)
				_ = sess.Exit(0)
			}()
		case "env":
			if sess.isHandled() {
				_ = req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			_ = gossh.Unmarshal(req.Payload, &kv)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			_ = req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			_ = gossh.Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "pty-req":
			if sess.isHandled() || sess.hasPty() {
				_ = req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				_ = req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
					_ = req.Reply(false, nil)
					continue
				}
			}

			sess.Lock()
			sess.pty = &ptyReq
			sess.winch = make(chan Window, 1)
			winch := sess.winch
			sess.Unlock()
			winch <- ptyReq.Window
			// The winch channel is closed by the deferred cleanup below, which
			// runs when the request channel closes. It is never closed while
			// the request loop may still send on it, so the window-change case
			// can enqueue safely.

			if sess.ptyHandler != nil {
				closer, err := sess.ptyHandler(sess.ctx, sess, ptyReq)
				if err != nil {
					// TODO: handle error
					_ = req.Reply(false, nil)
					continue
				}
				if closer != nil {
					// One shared closer for the request loop, the handler, and
					// this defer, so the PTY is released exactly once no matter
					// which of them gets there first.
					sess.setPtyClose(closer)
				}

				pty := sess.allocatedPty()
				if !sess.EmulatedPty() && pty != nil {
					go func() {
						defer recoverAndLog("panic resizing pty", nil, nil)
						for win := range winch {
							if err := resizePty(sess, win); err != nil {
								// TODO: handle error
								continue
							}
						}
					}()
				}
			}

			defer func() { //nolint:staticcheck // intentional: runs when reqs is closed
				// when reqs is closed
				close(winch)
				_ = sess.closePty()
			}()
			_ = req.Reply(ok, nil)
		case "window-change":
			sess.Lock()
			hasPty := sess.pty != nil
			win, _, ok := parseWindow(req.Payload)
			if hasPty && ok {
				sess.pty.Window = win
			}
			winch := sess.winch
			sess.Unlock()
			// Sent outside the lock: winch has a capacity of one, so holding
			// the lock across the send would let a slow consumer block every
			// Pty() behind it.
			if hasPty && ok {
				winch <- win
			}
			_ = req.Reply(hasPty && ok, nil)
		case agentRequestType:
			// TODO: option/callback to allow agent forwarding.
			// Recorded on the session as well as the connection context: agent
			// state is per-session, so an earlier session or connection can
			// never make a later one report AgentRequested.
			sess.Lock()
			sess.agentRequested = true
			sess.Unlock()
			SetAgentRequested(sess.ctx)
			_ = req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			_ = req.Reply(ok, nil)
			sess.Unlock()
		default:
			slog.Debug("ssh: unknown session request", "type", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (sess *session) ptyAllocate(term string, win Window, modes gossh.TerminalModes) (func() error, error) {
	p, err := newPty(sess.ctx, term, win, modes)
	if err != nil {
		return nil, err
	}

	sess.Lock()
	sess.pty = &Pty{
		Term:   term,
		Window: win,
		Modes:  modes,
		impl:   p,
	}
	sess.Unlock()

	return p.Close, nil
}

func resizePty(sess *session, win Window) error {
	sess.Lock()
	pty := sess.pty
	sess.Unlock()
	if pty == nil {
		return nil
	}

	return pty.Resize(win.Width, win.Height)
}

// isHandled reports whether a shell, exec, or subsystem request has been
// accepted. The request loop mutates it and the handler goroutine reads it, so
// both sides take the lock.
func (sess *session) isHandled() bool {
	sess.Lock()
	defer sess.Unlock()
	return sess.handled
}

// setHandled marks the session as having accepted a shell, exec, or subsystem.
func (sess *session) setHandled() {
	sess.Lock()
	sess.handled = true
	sess.Unlock()
}

// hasPty reports whether a PTY request has already been accepted.
func (sess *session) hasPty() bool {
	sess.Lock()
	defer sess.Unlock()
	return sess.pty != nil
}

// allocatedPty returns the PTY this session allocated, or nil if it has none.
func (sess *session) allocatedPty() *Pty {
	sess.Lock()
	defer sess.Unlock()
	if sess.pty == nil || sess.pty.IsZero() {
		return nil
	}
	return sess.pty
}

// setPtyClose installs the PTY's closer, wrapped so that every teardown path
// (request loop, handler goroutine, panic recovery) releases it exactly once.
func (sess *session) setPtyClose(closer func() error) {
	sess.Lock()
	defer sess.Unlock()
	if sess.ptyClose == nil {
		sess.ptyClose = closeOnce(closerFunc(closer))
	}
}

// closePty releases the PTY allocated for this session, if any. It is safe to
// call from several goroutines and more than once.
func (sess *session) closePty() error {
	sess.Lock()
	closeFn := sess.ptyClose
	sess.Unlock()
	if closeFn == nil {
		return nil
	}
	return closeFn()
}

// closerFunc adapts a plain close function to io.Closer for closeOnce.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }
