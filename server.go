package ssh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	gossh "golang.org/x/crypto/ssh"
)

// ErrServerClosed is returned by the Server's Serve, ListenAndServe,
// and ListenAndServeTLS methods after a call to Shutdown or Close.
var ErrServerClosed = errors.New("ssh: Server closed")

// ErrServerShuttingDown is returned to work that arrives after Shutdown or
// Close has begun: new handshakes and new forwarding registrations are refused
// so that the drain has a bounded, definite set of sessions to wait for.
var ErrServerShuttingDown = errors.New("ssh: server is shutting down")

// forceCloseGrace bounds how long Shutdown waits for force-closed connections
// to unwind after its context expired. The caller already gave up waiting, so
// this only exists to return with teardown underway rather than mid-flight.
const forceCloseGrace = time.Second

// closedChan returns a channel that is already closed, so a wait on it returns
// immediately.
func closedChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// ShutdownError is returned by Server.Shutdown when the context expired before
// every active session finished. The remaining sessions were force-closed;
// Residual reports how many were still active when the deadline was reached.
type ShutdownError struct {
	// Residual is the number of sessions still active at the deadline.
	Residual int
	// Connections is the number of connections still open at the deadline.
	Connections int
	// Forwards is the number of reverse-forward listeners still registered at
	// the deadline.
	Forwards int
	// Err is the reason the drain stopped, normally context.DeadlineExceeded.
	Err error
}

func (e *ShutdownError) Error() string {
	return fmt.Sprintf("ssh: shutdown did not complete with %d session(s), %d connection(s), and %d forward(s) remaining: %v",
		e.Residual, e.Connections, e.Forwards, e.Err)
}

// Unwrap exposes the context error so errors.Is(err, context.DeadlineExceeded)
// keeps working for callers that used to compare Shutdown's result directly.
func (e *ShutdownError) Unwrap() error {
	return e.Err
}

// SubsystemHandler is a handler for a given SSH subsystem.
type SubsystemHandler func(s Session)

// DefaultSubsystemHandlers is the default set of subsystem handlers.
var DefaultSubsystemHandlers = map[string]SubsystemHandler{}

// RequestHandler is a callback for custom global SSH requests.
type RequestHandler func(ctx Context, srv *Server, req *gossh.Request) (ok bool, payload []byte)

// DefaultRequestHandlers is the default set of request handlers.
var DefaultRequestHandlers = map[string]RequestHandler{}

// ChannelHandler is a callback for custom channel types.
type ChannelHandler func(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context)

// DefaultChannelHandlers is the default set of channel handlers.
var DefaultChannelHandlers = map[string]ChannelHandler{
	"session": DefaultSessionHandler,
}

var permissionsPublicKeyExt = "gliderlabs/ssh.PublicKey"

// ErrPermissionDenied is returned when authentication fails.
var ErrPermissionDenied = errors.New("permission denied")

func ensureNoPKInPermissions(ctx Context) error {
	if _, ok := ctx.Permissions().Extensions[permissionsPublicKeyExt]; ok {
		return errors.New("misconfigured server: public key incorrectly set")
	}

	return nil
}

// Server defines parameters for running an SSH server. The zero value for
// Server is a valid configuration. When both PasswordHandler and
// PublicKeyHandler are nil, no client authentication is performed.
type Server struct {
	Addr        string   // TCP address to listen on, ":22" if empty
	Handler     Handler  // handler to invoke, ssh.DefaultHandler if nil
	HostSigners []Signer // private keys for the host key, must have at least one
	Version     string   // server version to be sent before the initial handshake
	Banner      string   // server banner

	BannerHandler                 BannerHandler                 // server banner handler, overrides Banner
	KeyboardInteractiveHandler    KeyboardInteractiveHandler    // keyboard-interactive authentication handler
	PasswordHandler               PasswordHandler               // password authentication handler
	PublicKeyHandler              PublicKeyHandler              // public key authentication handler
	PtyCallback                   PtyCallback                   // callback for allocating and allowing PTY sessions, ssh.EmulatePtyCallback if nil
	PtyHandler                    PtyHandler                    // pty allocation handler, ssh.emulatePtyHandler if nil
	ConnCallback                  ConnCallback                  // optional callback for wrapping net.Conn before handling
	LocalPortForwardingCallback   LocalPortForwardingCallback   // callback for allowing local port forwarding, denies all if nil
	ReversePortForwardingCallback ReversePortForwardingCallback // callback for allowing reverse port forwarding, denies all if nil
	ServerConfigCallback          ServerConfigCallback          // callback for configuring detailed SSH options
	SessionRequestCallback        SessionRequestCallback        // callback for allowing or denying SSH sessions

	ConnectionFailedCallback ConnectionFailedCallback // callback to report connection failures
	ConnectionCloseCallback  ConnectionCloseCallback  // callback to report connection close

	HandshakeTimeout time.Duration // connection timeout until successful handshake, none if empty
	IdleTimeout      time.Duration // connection timeout when no activity, none if empty
	MaxTimeout       time.Duration // absolute connection timeout, none if empty

	EnableProxyProtocol bool // Enable support for HA Proxy's and NGinx's PROXY protocol

	// ChannelHandlers allow overriding the built-in session handlers or provide
	// extensions to the protocol, such as tcpip forwarding. By default only the
	// "session" handler is enabled.
	ChannelHandlers map[string]ChannelHandler

	// RequestHandlers allow overriding the server-level request handlers or
	// provide extensions to the protocol, such as tcpip forwarding. By default
	// no handlers are enabled.
	RequestHandlers map[string]RequestHandler

	// SubsystemHandlers are handlers which are similar to the usual SSH command
	// handlers, but handle named subsystems.
	SubsystemHandlers map[string]SubsystemHandler

	listenerWg sync.WaitGroup
	mu         sync.RWMutex
	started    atomic.Bool
	draining   atomic.Bool
	generation atomic.Uint64
	listeners  map[net.Listener]struct{}
	conns      map[net.Conn]struct{}
	sessions   map[*session]struct{}
	forwards   map[*forwardEntry]struct{}
	// sessionsDrained is closed when the last tracked session ends. It is
	// created when the first session registers and replaced after each drain,
	// so Shutdown can wait for the set it observed to become empty.
	sessionsDrained chan struct{}
	connWg          sync.WaitGroup
	doneChan        chan struct{}
}

// nextGeneration returns a new monotonic connection generation. Generations
// are server-scoped so that they order every connection the server serves.
func (srv *Server) nextGeneration() uint64 {
	return srv.generation.Add(1)
}

// isShuttingDown reports whether Close or Shutdown has begun. New handshakes
// and new forwarding registrations are refused while it is true.
func (srv *Server) isShuttingDown() bool {
	return srv.draining.Load()
}

// trackConn records a connection for as long as handleConn is serving it,
// including before the handshake completes. Tracking it from the start means
// Shutdown can force-close a connection that is stuck in a handshake instead
// of waiting on it, and that a connection racing with Shutdown is either
// refused or observed. Adding returns false when the server is already
// draining, in which case the caller must not serve the connection. Removing
// is idempotent.
func (srv *Server) trackConn(c net.Conn, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.conns == nil {
		srv.conns = make(map[net.Conn]struct{})
	}
	if add {
		if srv.draining.Load() {
			return false
		}
		srv.conns[c] = struct{}{}
		srv.connWg.Add(1)
		return true
	}
	if _, ok := srv.conns[c]; !ok {
		return true
	}
	delete(srv.conns, c)
	srv.connWg.Done()
	return true
}

// trackSession registers sess as active. It returns false when the server is
// shutting down, which keeps the set Shutdown waits for closed: once the
// draining flag is set, no new session can join it. Unregistering is
// idempotent, so a late cleanup from a session that already ended cannot
// signal the drain twice.
func (srv *Server) trackSession(sess *session, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.sessions == nil {
		srv.sessions = make(map[*session]struct{})
	}
	if add {
		if srv.draining.Load() {
			return false
		}
		if len(srv.sessions) == 0 && srv.sessionsDrained == nil {
			srv.sessionsDrained = make(chan struct{})
		}
		srv.sessions[sess] = struct{}{}
		return true
	}
	if _, ok := srv.sessions[sess]; !ok {
		return true
	}
	delete(srv.sessions, sess)
	if len(srv.sessions) == 0 && srv.sessionsDrained != nil {
		close(srv.sessionsDrained)
		srv.sessionsDrained = nil
	}
	return true
}

// closeTrackedConns closes every connection handleConn is currently serving,
// including ones that have not finished their handshake. It returns how many
// were closed. New connections are refused while draining, so this set does
// not grow after the snapshot.
func (srv *Server) closeTrackedConns() int {
	srv.mu.Lock()
	conns := make([]net.Conn, 0, len(srv.conns))
	for c := range srv.conns {
		conns = append(conns, c)
	}
	srv.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	// Reverse-forward listeners belong to connections, so tearing down the
	// connections without their listeners would leave the bound addresses
	// occupied. Close them here; each removal is idempotent. Only connections
	// are counted in the return value.
	srv.closeTrackedForwards()
	return len(conns)
}

// trackForward registers a reverse-forward listener with the server so that
// Close can tear it down. Registration fails once draining has begun, under
// the same lock that guards the drain decision, so a forward racing with
// Shutdown cannot be created after the server stopped accepting work.
func (srv *Server) trackForward(entry *forwardEntry, add bool) bool {
	if entry == nil {
		return true
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.forwards == nil {
		srv.forwards = make(map[*forwardEntry]struct{})
	}
	if add {
		if srv.draining.Load() {
			return false
		}
		srv.forwards[entry] = struct{}{}
		return true
	}
	delete(srv.forwards, entry)
	return true
}

// closeTrackedForwards force-closes every reverse-forward listener still
// registered. It returns how many it closed.
func (srv *Server) closeTrackedForwards() int {
	srv.mu.Lock()
	entries := make([]*forwardEntry, 0, len(srv.forwards))
	for entry := range srv.forwards {
		entries = append(entries, entry)
		delete(srv.forwards, entry)
	}
	srv.mu.Unlock()

	for _, entry := range entries {
		entry.stop()
		_ = entry.close()
	}
	return len(entries)
}

func (srv *Server) ensureHostSigner() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.HostSigners) == 0 {
		signer, err := generateSigner()
		if err != nil {
			return err
		}
		srv.HostSigners = append(srv.HostSigners, signer)
	}
	return nil
}

func (srv *Server) ensureHandlers() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.RequestHandlers == nil {
		srv.RequestHandlers = map[string]RequestHandler{}
		for k, v := range DefaultRequestHandlers {
			srv.RequestHandlers[k] = v
		}
	}
	if srv.ChannelHandlers == nil {
		srv.ChannelHandlers = map[string]ChannelHandler{}
		for k, v := range DefaultChannelHandlers {
			srv.ChannelHandlers[k] = v
		}
	}
	if srv.SubsystemHandlers == nil {
		srv.SubsystemHandlers = map[string]SubsystemHandler{}
		for k, v := range DefaultSubsystemHandlers {
			srv.SubsystemHandlers[k] = v
		}
	}
}

func (srv *Server) config(ctx Context) *gossh.ServerConfig {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var config *gossh.ServerConfig
	if srv.ServerConfigCallback == nil {
		config = &gossh.ServerConfig{}
	} else {
		config = srv.ServerConfigCallback(ctx)
	}
	for _, signer := range srv.HostSigners {
		config.AddHostKey(signer)
	}
	if srv.PasswordHandler == nil && srv.PublicKeyHandler == nil && srv.KeyboardInteractiveHandler == nil &&
		config.PasswordCallback == nil && config.PublicKeyCallback == nil && config.KeyboardInteractiveCallback == nil {
		config.NoClientAuth = true
	}
	if srv.PtyHandler == nil {
		srv.PtyHandler = emulatePtyHandler
	}
	if srv.Version != "" {
		config.ServerVersion = "SSH-2.0-" + srv.Version
	}
	if srv.Banner != "" {
		config.BannerCallback = func(_ gossh.ConnMetadata) string {
			return srv.Banner
		}
	}
	if srv.BannerHandler != nil {
		config.BannerCallback = func(conn gossh.ConnMetadata) string {
			applyConnMetadata(ctx, conn)
			return srv.BannerHandler(ctx)
		}
	}
	if srv.PasswordHandler != nil {
		config.PasswordCallback = func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			resetPermissions(ctx)
			applyConnMetadata(ctx, conn)
			err := ensureNoPKInPermissions(ctx)
			if err != nil {
				return ctx.Permissions().Permissions, err
			}
			ok := srv.PasswordHandler(ctx, string(password))
			if !ok {
				return ctx.Permissions().Permissions, ErrPermissionDenied
			}
			return ctx.Permissions().Permissions, nil
		}
	}
	if srv.PublicKeyHandler != nil {
		config.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			resetPermissions(ctx)
			applyConnMetadata(ctx, conn)
			err := ensureNoPKInPermissions(ctx)
			if err != nil {
				return ctx.Permissions().Permissions, err
			}
			ok := srv.PublicKeyHandler(ctx, key)
			if !ok {
				return ctx.Permissions().Permissions, ErrPermissionDenied
			}

			pkStr := base64.StdEncoding.EncodeToString(key.Marshal())
			if ctx.Permissions().Extensions == nil {
				ctx.Permissions().Extensions = map[string]string{}
			}
			ctx.Permissions().Extensions[permissionsPublicKeyExt] = pkStr

			return ctx.Permissions().Permissions, nil
		}
	}
	if srv.KeyboardInteractiveHandler != nil {
		config.KeyboardInteractiveCallback = func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			resetPermissions(ctx)
			applyConnMetadata(ctx, conn)
			ok := srv.KeyboardInteractiveHandler(ctx, challenger)
			err := ensureNoPKInPermissions(ctx)
			if err != nil {
				return ctx.Permissions().Permissions, err
			}
			if !ok {
				return ctx.Permissions().Permissions, ErrPermissionDenied
			}
			return ctx.Permissions().Permissions, nil
		}
	}
	return config
}

// Handle sets the Handler for the server.
func (srv *Server) Handle(fn Handler) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.Handler = fn
}

// Close immediately closes all active listeners and all active
// connections. New handshakes and forwarding registrations are refused once
// Close has begun.
//
// Close returns any error returned from closing the Server's
// underlying Listener(s).
func (srv *Server) Close() error {
	srv.mu.Lock()
	// Stop accepting new work under the same lock connection and session
	// registration use, so everything closed below is the whole set and
	// nothing can join it afterwards.
	srv.draining.Store(true)
	srv.closeDoneChanLocked()
	err := srv.closeListenersLocked()
	srv.mu.Unlock()

	srv.closeTrackedConns()
	return err
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first refusing new handshakes and
// forwarding registrations, closing all open listeners, and then waiting for
// the sessions that were active when it started to finish.
//
// If the provided context expires before the shutdown is complete, the
// remaining sessions, connections, and forward listeners are force-closed and
// a *ShutdownError is returned that reports how many were still active. The
// error wraps the context error, so errors.Is(err, context.DeadlineExceeded)
// still holds.
func (srv *Server) Shutdown(ctx context.Context) error {
	srv.mu.Lock()
	// Refuse new handshakes and forwarding under the registration lock, so the
	// session and connection sets snapshotted below are final. Anything that
	// registered before this point has already completed its WaitGroup Add;
	// anything after it is refused.
	srv.draining.Store(true)
	lnerr := srv.closeListenersLocked()
	srv.closeDoneChanLocked()
	// Snapshot the wait gate for the sessions already active. trackSession
	// closes it when the tracked set empties; if no session is active yet the
	// gate is nil and that state is already drained.
	drained := srv.sessionsDrained
	if drained == nil {
		drained = closedChan()
	}
	connWg := &srv.connWg
	srv.mu.Unlock()

	finished := make(chan struct{}, 1)
	go func() {
		srv.listenerWg.Wait()
		// Wait for the sessions that were active when Shutdown started.
		// Connections that never carried a session must not keep the drain
		// open: a client can hold an idle connection indefinitely.
		<-drained
		// No new session can register now, so every remaining connection is
		// either idle or still handshaking. Close them and wait for their
		// goroutines to unwind.
		srv.closeTrackedConns()
		connWg.Wait()
		finished <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		srv.mu.RLock()
		residualSessions := len(srv.sessions)
		residualConns := len(srv.conns)
		residualForwards := len(srv.forwards)
		srv.mu.RUnlock()

		// Force-close what is left, including the forward listeners, so no
		// bound address outlives the shutdown. The counts were taken before
		// closing because they are this call's report, not a live reading.
		srv.closeTrackedConns()

		unwound := make(chan struct{}, 1)
		go func() {
			connWg.Wait()
			unwound <- struct{}{}
		}()
		select {
		case <-unwound:
		case <-time.After(forceCloseGrace):
		}

		return &ShutdownError{
			Residual:    residualSessions,
			Connections: residualConns,
			Forwards:    residualForwards,
			Err:         ctx.Err(),
		}
	case <-finished:
		return lnerr
	}
}

// Serve accepts incoming connections on the Listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and then
// calls srv.Handler to handle sessions.
//
// Serve always returns a non-nil error.
func (srv *Server) Serve(l net.Listener) error {
	if srv.EnableProxyProtocol {
		_, ok := l.(*proxyproto.Listener)
		if !ok {
			l = &proxyproto.Listener{Listener: l}
		}
	}

	srv.ensureHandlers()
	defer func() { _ = l.Close() }()
	if err := srv.ensureHostSigner(); err != nil {
		return err
	}
	if srv.Handler == nil {
		srv.Handler = DefaultHandler
	}
	var tempDelay time.Duration

	if !srv.trackListener(l, true) {
		return ErrServerClosed
	}
	srv.started.Store(true)
	defer srv.trackListener(l, false)
	for {
		conn, e := l.Accept()
		if e != nil {
			select {
			case <-srv.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := e.(net.Error); ok && ne.Temporary() { //nolint:staticcheck // SA1019: same pattern as net/http
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if limit := 1 * time.Second; tempDelay > limit {
					tempDelay = limit
				}
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		go srv.HandleConn(conn)
	}
}

// HandleConn handles a new SSH connection.
//
// A panic while handling the connection is recovered and logged rather than
// allowed to escape. Connections are served on their own goroutine, and Go has
// no process-wide panic handler, so an unrecovered panic here would terminate
// the whole server process along with every other connection. That includes
// panics raised inside the SSH handshake, before authentication has happened,
// which would otherwise let an unauthenticated client take the server down.
func (srv *Server) HandleConn(newConn net.Conn) {
	defer recoverAndLog("panic serving connection", newConn, func() {
		// The deferred close inside handleConn did not get to run.
		_ = newConn.Close()
	})

	srv.handleConn(newConn)
}

// recoverAndLog recovers a panic on the current goroutine, logs it with a
// stack trace, and runs cleanup if one is given.
//
// This must be deferred directly on the goroutine to be protected: a recover
// only sees panics unwinding its own stack, so every goroutine the server
// starts needs its own call.
func recoverAndLog(msg string, conn net.Conn, cleanup func()) {
	r := recover()
	if r == nil {
		return
	}
	slog.Error("ssh: "+msg,
		"remote", remoteAddrString(conn),
		"panic", r,
		"stack", string(debug.Stack()),
	)
	if cleanup != nil {
		// Cleanup runs while already unwinding a panic, so a second panic
		// raised here would escape this recover and kill the process, undoing
		// the containment. Contain it separately.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("ssh: panic during "+msg+" cleanup", "panic", r)
			}
		}()
		cleanup()
	}
}

// remoteAddrString returns conn's remote address for logging, tolerating a nil
// conn or address so that the panic handler cannot itself panic.
func remoteAddrString(conn net.Conn) string {
	if conn == nil {
		return "unknown"
	}
	if addr := conn.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return "unknown"
}

func (srv *Server) handleConn(newConn net.Conn) {
	// A new handshake always starts from a brand-new context with its own
	// generation. Nothing authentication-related survives from a previous
	// connection: no user, public key, permissions, or agent-request state has
	// a place to live outside this context.
	ctx, cancel := newContext(srv)
	if srv.ConnCallback != nil {
		cbConn := srv.ConnCallback(ctx, newConn)
		if cbConn == nil {
			_ = newConn.Close()
			return
		}
		newConn = cbConn
	}
	conn := &serverConn{
		Conn:          newConn,
		idleTimeout:   srv.IdleTimeout,
		closeCanceler: cancel,
	}
	if srv.MaxTimeout > 0 {
		conn.maxDeadline = time.Now().Add(srv.MaxTimeout)
	}
	if srv.HandshakeTimeout > 0 {
		conn.setHandshakeDeadline(time.Now().Add(srv.HandshakeTimeout))
	}
	conn.updateDeadline()

	// Refuse the handshake outright once draining has begun. Tracking happens
	// under the same lock that Shutdown uses to take its snapshot, so a
	// connection either registers before the drain starts and is waited for /
	// force-closed, or is turned away here.
	if !srv.trackConn(conn, true) {
		_ = conn.Close()
		return
	}
	defer srv.trackConn(conn, false)
	defer func() { _ = conn.Close() }()
	defer func() {
		if srv.ConnectionCloseCallback != nil {
			srv.ConnectionCloseCallback(conn)
		}
	}()
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, srv.config(ctx))
	if err != nil {
		if srv.ConnectionFailedCallback != nil {
			srv.ConnectionFailedCallback(conn, err)
		}
		return
	}
	conn.clearHandshakeDeadline()

	if err := extractPublicKeyFromPermissions(ctx, sshConn); err != nil {
		if srv.ConnectionFailedCallback != nil {
			srv.ConnectionFailedCallback(conn, err)
		}
		return
	}

	// Additionally, now that the connection was authed, we can take the
	// permissions off of the gossh.Conn and re-attach them to the Permissions
	// object stored in the Context.
	ctx.Permissions().Permissions = sshConn.Permissions

	ctx.SetValue(ContextKeyConn, sshConn)
	applyConnMetadata(ctx, sshConn)
	// go gossh.DiscardRequests(reqs)
	go func() {
		defer recoverAndLog("panic handling requests", conn, nil)
		srv.handleRequests(ctx, reqs)
	}()
	for ch := range chans {
		handler := srv.ChannelHandlers[ch.ChannelType()]
		if handler == nil {
			handler = srv.ChannelHandlers["default"]
		}
		if handler == nil {
			_ = ch.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		go func(ch gossh.NewChannel) {
			defer recoverAndLog("panic handling channel", conn, nil)
			handler(srv, sshConn, ch, ctx)
		}(ch)
	}
}

func (srv *Server) handleRequests(ctx Context, in <-chan *gossh.Request) {
	for req := range in {
		handler := srv.RequestHandlers[req.Type]
		if handler == nil {
			handler = srv.RequestHandlers["default"]
		}
		if handler == nil {
			_ = req.Reply(false, nil)
			continue
		}
		/*reqCtx, cancel := context.WithCancel(ctx)
		defer cancel() */
		ret, payload := handler(ctx, srv, req)
		_ = req.Reply(ret, payload)
	}
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle incoming connections. If srv.Addr is blank, ":22" is used.
// ListenAndServe always returns a non-nil error.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":22"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// AddHostKey adds a private key as a host key. If an existing host key exists
// with the same algorithm, it is overwritten. Each server config must have at
// least one host key.
func (srv *Server) AddHostKey(key Signer) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// these are later added via AddHostKey on ServerConfig, which performs the
	// check for one of every algorithm.

	// This check is based on the AddHostKey method from the x/crypto/ssh
	// library. This allows us to only keep one active key for each type on a
	// server at once. So, if you're dynamically updating keys at runtime, this
	// list will not keep growing.
	for i, k := range srv.HostSigners {
		if k.PublicKey().Type() == key.PublicKey().Type() {
			srv.HostSigners[i] = key
			return
		}
	}

	srv.HostSigners = append(srv.HostSigners, key)
}

// SetOption runs a functional option against the server.
// It returns an error if the server has already been started.
func (srv *Server) SetOption(option Option) error {
	if srv.started.Load() {
		return fmt.Errorf("ssh: cannot set option after server has started")
	}

	// NOTE: there is a potential race here for any option that doesn't call an
	// internal method. We can't actually lock here because if something calls
	// (as an example) AddHostKey, it will deadlock.

	// srv.mu.Lock()
	// defer srv.mu.Unlock()

	return option(srv)
}

func (srv *Server) getDoneChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return srv.getDoneChanLocked()
}

func (srv *Server) getDoneChanLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

func (srv *Server) closeDoneChanLocked() {
	ch := srv.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by srv.mu.
		close(ch)
	}
}

func (srv *Server) closeListenersLocked() error {
	var err error
	for ln := range srv.listeners {
		if cerr := ln.Close(); cerr != nil && err == nil {
			err = cerr
		}
		delete(srv.listeners, ln)
	}
	return err
}

// trackListener registers ln so Shutdown and Close can close it. Adding fails
// once the server is draining: a Serve that races with Shutdown must not keep
// accepting connections after the drain started.
func (srv *Server) trackListener(ln net.Listener, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listeners == nil {
		srv.listeners = make(map[net.Listener]struct{})
	}
	if add {
		if srv.draining.Load() {
			return false
		}
		srv.listeners[ln] = struct{}{}
		srv.listenerWg.Add(1)
		return true
	}
	// The listener is always removed from the set by whoever closes it, so the
	// delete below may be a no-op. The Done must still run: Serve calls this
	// exactly once when it returns, and closeListenersLocked never touches the
	// WaitGroup.
	delete(srv.listeners, ln)
	srv.listenerWg.Done()
	return true
}

// extractPublicKeyFromPermissions re-parses the public key from the
// permissions extensions and stores it in the context.
func extractPublicKeyFromPermissions(ctx Context, sshConn *gossh.ServerConn) error {
	if sshConn.Permissions == nil {
		return nil
	}
	keyData, ok := sshConn.Permissions.Extensions[permissionsPublicKeyExt]
	if !ok {
		return nil
	}
	decodedData, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return err
	}
	key, err := gossh.ParsePublicKey(decodedData)
	if err != nil {
		return err
	}
	ctx.SetValue(ContextKeyPublicKey, key)
	return nil
}
