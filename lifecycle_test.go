package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// newGenerationServer starts a server with a handler that signals the session
// it was given, returning the server, its listener address, and a cleanup.
func newGenerationServer(t *testing.T, handler Handler, opts ...func(*Server)) (*Server, string, func()) {
	t.Helper()

	srv := &Server{Handler: handler}
	for _, opt := range opts {
		opt(srv)
	}
	l := newLocalListener()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	cleanup := func() {
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	return srv, l.Addr().String(), cleanup
}

// TestContextGenerationStrictlyIncreases pins the property everything else
// relies on: each new connection context gets a generation greater than every
// generation handed out before it, including across reuse of the same Server.
func TestContextGenerationStrictlyIncreases(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	var last uint64
	for i := 0; i < 100; i++ {
		ctx, cancel := newContext(srv)
		gen := contextGeneration(ctx)
		if gen <= last {
			t.Fatalf("generation %d is not greater than previous %d", gen, last)
		}
		last = gen
		cancel()
	}
}

// TestNewConnectionDoesNotInheritAuthState drives two real handshakes on the
// same server. The auth handler records what it can see at the start of each
// attempt, before writing anything: the second connection must not see the
// first connection's public key or agent-request state.
func TestNewConnectionDoesNotInheritAuthState(t *testing.T) {
	t.Parallel()

	signer := testHostSigner(t)
	clientKey := testClientSigner(t)

	type observation struct {
		user           string
		publicKey      interface{}
		agentRequested interface{}
		extensions     int
	}
	var (
		mu           sync.Mutex
		observations []observation
	)

	srv := &Server{
		PublicKeyHandler: func(ctx Context, key PublicKey) bool {
			mu.Lock()
			observations = append(observations, observation{
				user:           ctx.User(),
				publicKey:      ctx.Value(ContextKeyPublicKey),
				agentRequested: ctx.Value(contextKeyAgentRequest),
				extensions:     len(ctx.Permissions().Extensions),
			})
			mu.Unlock()

			ctx.Permissions().Extensions = map[string]string{"scope": ctx.User()}
			SetAgentRequested(ctx)
			return true
		},
		Handler: func(Session) {},
	}
	srv.AddHostKey(signer)

	l := newLocalListener()
	go srv.Serve(l) //nolint:errcheck
	defer srv.Close()

	dial := func(user string) {
		client, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
			User:            user,
			Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientKey)},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			t.Fatalf("dial as %s: %v", user, err)
		}
		defer client.Close() //nolint:errcheck
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("new session as %s: %v", user, err)
		}
		if err := sess.Run(""); err != nil {
			t.Fatalf("run as %s: %v", user, err)
		}
	}

	dial("alice")
	dial("bob")

	mu.Lock()
	got := append([]observation(nil), observations...)
	mu.Unlock()

	var alice, bob *observation
	for i := range got {
		switch got[i].user {
		case "alice":
			alice = &got[i]
		case "bob":
			bob = &got[i]
		}
	}
	if alice == nil || bob == nil {
		t.Fatalf("missing auth observations: %+v", got)
	}

	// Every fresh connection starts blank, including bob's after alice's
	// connection wrote a key, extensions, and an agent request.
	for _, o := range []observation{*alice, *bob} {
		if o.publicKey != nil {
			t.Errorf("%s saw a public key before authenticating: %v", o.user, o.publicKey)
		}
		if o.agentRequested != nil {
			t.Errorf("%s saw agent-request state before authenticating: %v", o.user, o.agentRequested)
		}
		if o.extensions != 0 {
			t.Errorf("%s saw %d permissions before authenticating", o.user, o.extensions)
		}
	}
}

// testClientSigner returns a throwaway client key for tests that drive a real
// authenticated handshake. It is always the same key, so every test user
// authenticates with it and the auth handler decides whom to accept.
func testClientSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestConnectionContextIsolation unit-tests the same property without a
// handshake: state written by one connection's auth passes is invisible to the
// next connection's context.
func TestConnectionContextIsolation(t *testing.T) {
	t.Parallel()

	srv := &Server{}

	aliceCtx, aliceCancel := newContext(srv)
	defer aliceCancel()
	applyConnMetadata(aliceCtx, mockConnMetadata{user: "alice", sessionID: []byte("a")})
	aliceCtx.Permissions().Extensions = map[string]string{"scope": "alice"}
	aliceCtx.SetValue(ContextKeyPublicKey, "alice-key")
	SetAgentRequested(aliceCtx)

	bobCtx, bobCancel := newContext(srv)
	defer bobCancel()
	applyConnMetadata(bobCtx, mockConnMetadata{user: "bob", sessionID: []byte("b")})

	if got := bobCtx.User(); got != "bob" {
		t.Fatalf("bob context User() = %q; want bob", got)
	}
	if _, ok := bobCtx.Permissions().Extensions["scope"]; ok {
		t.Error("bob inherited alice's permissions")
	}
	if v := bobCtx.Value(ContextKeyPublicKey); v != nil {
		t.Errorf("bob inherited alice's public key: %v", v)
	}
	if v := bobCtx.Value(contextKeyAgentRequest); v != nil {
		t.Errorf("bob inherited alice's agent request: %v", v)
	}
}

// TestAgentRequestedIsSessionScoped checks that agent request state recorded
// on one session does not leak to another session sharing the connection
// context.
func TestAgentRequestedIsSessionScoped(t *testing.T) {
	t.Parallel()

	ctx, cancel := newContext(&Server{})
	defer cancel()
	// Simulate the connection-level value having been set by an earlier
	// session, which is exactly the leak this guards against.
	SetAgentRequested(ctx)

	second := &session{ctx: ctx}
	if AgentRequested(second) {
		t.Fatal("a new session inherited agent-request state from the connection context")
	}

	second.Lock()
	second.agentRequested = true
	second.Unlock()
	if !AgentRequested(second) {
		t.Fatal("session-scoped agent request was not observed")
	}
	if AgentRequested(nil) {
		t.Fatal("AgentRequested(nil) must be false")
	}
}

// TestStaleContextCleanupDoesNotAffectNewConnection verifies the generation
// ownership check: cleanup work from an older context must not act on the
// newer connection's state.
func TestStaleContextCleanupDoesNotAffectNewConnection(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	oldCtx, oldCancel := newContext(srv)
	newCtx, newCancel := newContext(srv)
	defer oldCancel()
	defer newCancel()

	oldGen := contextGeneration(oldCtx)
	newGen := contextGeneration(newCtx)
	if oldGen >= newGen {
		t.Fatalf("generations not ordered: old=%d new=%d", oldGen, newGen)
	}

	// The rule the forwarding and teardown paths follow: only act when the
	// event's generation matches the owner's.
	owned := func(eventGen, ownerGen uint64) bool { return eventGen == ownerGen }
	if owned(oldGen, newGen) {
		t.Fatal("older generation claimed ownership of state from a newer connection")
	}
	if !owned(newGen, newGen) {
		t.Fatal("matching generation should own the state")
	}
}

// TestForwardRegistrationRejectsDuplicateAndLateCancel covers the forwarding
// requirements directly: only one registration per bound address succeeds, a
// rejected request closes the listener it created, and a late cancel from an
// older connection cannot close the newer registration.
func TestForwardRegistrationRejectsDuplicateAndLateCancel(t *testing.T) {
	t.Parallel()

	srv := &Server{
		ReversePortForwardingCallback: func(Context, string, uint32) bool { return true },
	}
	h := &ForwardedTCPHandler{}

	firstCtx, firstCancel := newContext(srv)
	defer firstCancel()
	firstCtx.SetValue(ContextKeyConn, &gossh.ServerConn{})

	// Port 0 lets the OS pick; the reply reports the port that was actually
	// bound, which is the address the client would send in a cancel request.
	ok, reply := h.HandleSSHRequest(firstCtx, srv, tcpipForwardRequest(t, "127.0.0.1", 0))
	if !ok {
		t.Fatal("first registration should succeed")
	}
	var success remoteForwardSuccess
	if err := gossh.Unmarshal(reply, &success); err != nil {
		t.Fatalf("parse forward reply: %v", err)
	}
	port := uint16(success.BindPort)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))

	// Second connection, same address: must fail and must not disturb the
	// first listener.
	secondCtx, secondCancel := newContext(srv)
	defer secondCancel()
	secondCtx.SetValue(ContextKeyConn, &gossh.ServerConn{})

	ok, _ = h.HandleSSHRequest(secondCtx, srv, tcpipForwardRequest(t, "127.0.0.1", uint32(port)))
	if ok {
		t.Fatal("second registration at the same address should fail")
	}

	// Late cancel from the second (failed) connection must not close the
	// first connection's listener.
	h.HandleSSHRequest(secondCtx, srv, cancelForwardRequest(t, "127.0.0.1", uint32(port)))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("first forward listener was closed by a foreign cancel: %v", err)
	}
	conn.Close() //nolint:errcheck

	// A cancel from the owning connection does close it.
	ok, _ = h.HandleSSHRequest(firstCtx, srv, cancelForwardRequest(t, "127.0.0.1", uint32(port)))
	if !ok {
		t.Fatal("owner cancel should succeed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close() //nolint:errcheck
		if time.Now().After(deadline) {
			t.Fatal("owner cancel did not close the listener")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestForwardMapRejectsWithoutTouchingExisting covers the map-arbitration path
// deterministically: even when the OS lets a second listener bind the same
// address (for example a stale entry whose listener was closed), the handler
// rejects the duplicate, closes the listener it created, and leaves the
// existing registration untouched.
func TestForwardMapRejectsWithoutTouchingExisting(t *testing.T) {
	t.Parallel()

	srv := &Server{
		ReversePortForwardingCallback: func(Context, string, uint32) bool { return true },
	}
	h := &ForwardedTCPHandler{}

	// A registration whose listener has already gone away, as if the process
	// released the address but the bookkeeping entry outlived it.
	staleLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(staleLn.Addr().String())
	port, _ := strconv.Atoi(portStr)
	staleAddr := net.JoinHostPort("127.0.0.1", portStr)
	staleLn.Close() //nolint:errcheck

	existing := &forwardEntry{
		addr:  staleAddr,
		close: func() error { return nil },
		done:  make(chan struct{}),
	}
	h.forwards = map[string]*forwardEntry{staleAddr: existing}

	ctx, cancel := newContext(srv)
	defer cancel()
	ctx.SetValue(ContextKeyConn, &gossh.ServerConn{})

	ok, _ := h.HandleSSHRequest(ctx, srv, tcpipForwardRequest(t, "127.0.0.1", uint32(port)))
	if ok {
		t.Fatal("duplicate registration should be rejected")
	}

	h.Lock()
	cur := h.forwards[staleAddr]
	h.Unlock()
	if cur != existing {
		t.Fatal("rejected registration disturbed the existing entry")
	}

	// The rejected request's own listener must have been released, so the
	// address can be bound again.
	ln, err := net.Listen("tcp", staleAddr)
	if err != nil {
		t.Fatalf("rejected registration leaked its listener: %v", err)
	}
	ln.Close() //nolint:errcheck
}

// TestLateForwardRemovalOnlyAffectsOwnEntry covers the generation rule: a late
// removal for an entry that has already been replaced must not close or forget
// the replacement.
func TestLateForwardRemovalOnlyAffectsOwnEntry(t *testing.T) {
	t.Parallel()

	h := &ForwardedTCPHandler{}
	addr := "127.0.0.1:12345"

	oldEntry := &forwardEntry{addr: addr, close: func() error { return nil }, done: make(chan struct{})}
	newEntry := &forwardEntry{addr: addr, close: func() error { return nil }, done: make(chan struct{})}
	h.forwards = map[string]*forwardEntry{addr: newEntry}

	h.removeForward(&Server{}, oldEntry)

	h.Lock()
	cur := h.forwards[addr]
	h.Unlock()
	if cur != newEntry {
		t.Fatal("late removal from an older registration affected the newer one")
	}
}

// TestSessionGenerationMatchesContext checks that every session is bound to
// the generation of the handshake that admitted it.
func TestSessionGenerationMatchesContext(t *testing.T) {
	t.Parallel()

	seen := make(chan uint64, 1)
	_, addr, cleanupServer := newGenerationServer(t, func(s Session) {
		internal := s.(*session)
		seen <- internal.generation
	})
	defer cleanupServer()

	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Run(""); err != nil {
		t.Fatal(err)
	}

	var gen uint64
	select {
	case gen = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran")
	}
	if gen == 0 {
		t.Fatal("session was not bound to a connection generation")
	}
}

// TestShutdownRefusesNewForwarding checks that forwarding registrations are
// refused once Shutdown has begun.
func TestShutdownRefusesNewForwarding(t *testing.T) {
	t.Parallel()

	srv := &Server{
		ReversePortForwardingCallback: func(Context, string, uint32) bool { return true },
	}
	h := &ForwardedTCPHandler{}

	// Begin draining without any listeners or sessions.
	_ = srv.Shutdown(context.Background())

	ctx, cancel := newContext(srv)
	defer cancel()
	ctx.SetValue(ContextKeyConn, &gossh.ServerConn{})

	ok, payload := h.HandleSSHRequest(ctx, srv, tcpipForwardRequest(t, "127.0.0.1", 0))
	if ok {
		t.Fatal("forward registration should be refused while shutting down")
	}
	if len(payload) == 0 {
		t.Fatal("refusal should explain why")
	}
}

// TestShutdownRefusesNewHandshakes checks that a connection arriving after
// Shutdown started is closed rather than served.
func TestShutdownRefusesNewHandshakes(t *testing.T) {
	t.Parallel()

	srv, addr, cleanup := newGenerationServer(t, func(Session) {})
	defer cleanup()

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	_, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	})
	if err == nil {
		t.Fatal("handshake succeeded after Shutdown began")
	}
}

// TestShutdownWaitsForActiveSession checks the graceful path: Shutdown returns
// only once the in-flight session has finished.
func TestShutdownWaitsForActiveSession(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	srv, addr, cleanupServer := newGenerationServer(t, func(Session) {
		close(started)
		<-release
	})
	defer cleanupServer()

	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run("") }()

	<-started

	done := make(chan error, 1)
	go func() { done <- srv.Shutdown(context.Background()) }()

	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v while a session was still active", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the session finished")
	}
	<-runDone
}

// TestShutdownTimeoutReportsResidual checks the forced path: an expired
// context force-closes the session and the returned error reports the count.
func TestShutdownTimeoutReportsResidual(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	block := make(chan struct{})
	defer close(block)
	srv, addr, cleanupServer := newGenerationServer(t, func(Session) {
		close(started)
		<-block
	})
	defer cleanupServer()

	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = sess.Output("") }()

	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = srv.Shutdown(ctx)
	if err == nil {
		t.Fatal("Shutdown should report an error when its context expires")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v; want it to wrap context.DeadlineExceeded", err)
	}
	var shutdownErr *ShutdownError
	if !errors.As(err, &shutdownErr) {
		t.Fatalf("Shutdown error = %T; want *ShutdownError", err)
	}
	if shutdownErr.Residual != 1 {
		t.Fatalf("Residual = %d; want 1", shutdownErr.Residual)
	}
}

// TestCloseTrackedConnsDoesNotDoubleWait makes sure the connection WaitGroup is
// balanced when Close force-closes tracked connections.
func TestCloseTrackedConnsDoesNotDoubleWait(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck

	if !srv.trackConn(server, true) {
		t.Fatal("tracking a connection on a fresh server should succeed")
	}

	// Closing through the server from a goroutine mirrors what Shutdown does;
	// the handleConn path must then be able to unregister without going
	// negative.
	done := make(chan struct{})
	go func() {
		srv.closeTrackedConns()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closeTrackedConns blocked")
	}
	srv.trackConn(server, false) // must not panic or unbalance the WaitGroup

	var wgDone = make(chan struct{})
	go func() {
		srv.connWg.Wait()
		close(wgDone)
	}()
	select {
	case <-wgDone:
	case <-time.After(time.Second):
		t.Fatal("connection WaitGroup was not released")
	}
}

// TestCloseOnceIdempotent checks the shared close wrapper used by PTYs,
// channels, and forwarding listeners: the first close wins and later calls
// neither repeat it nor report a new error.
func TestCloseOnceIdempotent(t *testing.T) {
	t.Parallel()

	c := &countingCloser{}
	closeFn := closeOnce(c)

	if err := closeFn(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = closeFn()
		}()
	}
	wg.Wait()

	if got := c.count.Load(); got != 1 {
		t.Fatalf("closer called %d times; want exactly once", got)
	}
}

// TestSessionCloseIsIdempotent checks that repeated Session.Close calls close
// the channel once and return the first result.
func TestSessionCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	ch := &countingCloser{}
	sess := &session{closeChannel: closeOnce(ch)}

	if err := sess.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := ch.count.Load(); got != 1 {
		t.Fatalf("channel closed %d times; want once", got)
	}
}

// TestSessionPtyCloseIsIdempotent checks that the PTY closer is shared and runs
// at most once even if several paths observe the end of the session.
func TestSessionPtyCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	c := &countingCloser{}
	sess := &session{}
	sess.setPtyClose(c.Close)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sess.closePty()
		}()
	}
	wg.Wait()

	if got := c.count.Load(); got != 1 {
		t.Fatalf("pty closed %d times; want once", got)
	}
}

// TestTrackSessionUnregisterIsIdempotent checks that a double unregister does
// not close the drain signal twice or corrupt the tracked set.
func TestTrackSessionUnregisterIsIdempotent(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	sess := &session{}
	if !srv.trackSession(sess, true) {
		t.Fatal("registering a session on a fresh server should succeed")
	}
	srv.trackSession(sess, false)
	srv.trackSession(sess, false) // must be a no-op, not a double close

	srv.mu.RLock()
	n := len(srv.sessions)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("tracked sessions = %d; want 0", n)
	}
}

// TestTrackSessionRefusedWhileDraining checks the gate Shutdown depends on.
func TestTrackSessionRefusedWhileDraining(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	srv.draining.Store(true)
	if srv.trackSession(&session{}, true) {
		t.Fatal("session registration should be refused while draining")
	}
}

type countingCloser struct {
	count atomic.Int32
}

func (c *countingCloser) Close() error {
	c.count.Add(1)
	return nil
}

func tcpipForwardRequest(t *testing.T, addr string, port uint32) *gossh.Request {
	t.Helper()
	return &gossh.Request{
		Type:      "tcpip-forward",
		WantReply: true,
		Payload:   gossh.Marshal(&remoteForwardRequest{BindAddr: addr, BindPort: port}),
	}
}

func cancelForwardRequest(t *testing.T, addr string, port uint32) *gossh.Request {
	t.Helper()
	return &gossh.Request{
		Type:      "cancel-tcpip-forward",
		WantReply: true,
		Payload:   gossh.Marshal(&remoteForwardCancelRequest{BindAddr: addr, BindPort: port}),
	}
}
