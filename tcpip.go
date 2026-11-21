package ssh

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType = "forwarded-tcpip"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2.
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// DirectTCPIPHandler can be enabled by adding it to the server's
// ChannelHandlers under direct-tcpip.
func DirectTCPIPHandler(srv *Server, _ *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = dconn.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	// Both copy loops race to observe the end of the connection. Closing
	// through a once makes the notification happen exactly once and keeps the
	// losing loop from double-closing a handle the other one already released.
	closeCh := closeOnce(ch)
	closeDest := closeOnce(dconn)
	go func() {
		defer recoverAndLog("panic proxying forwarded connection", nil, nil)
		defer closeCh()
		defer closeDest()
		_, _ = io.Copy(ch, dconn)
	}()
	go func() {
		defer recoverAndLog("panic proxying forwarded connection", nil, nil)
		defer closeCh()
		defer closeDest()
		_, _ = io.Copy(dconn, ch)
	}()
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// forwardEntry is one successful tcpip-forward registration. Entries are
// compared by identity so that a late event from an old registration cannot
// remove or close a newer listener that reused the same address.
type forwardEntry struct {
	ln         net.Listener
	addr       string
	generation uint64
	// owner is the connection that registered the forward. A cancel request is
	// honored only for the registration this connection owns.
	owner *gossh.ServerConn
	close func() error
	// done is closed when the entry is removed, releasing the context watcher
	// without waiting for the whole connection to end.
	done     chan struct{}
	doneOnce sync.Once
}

// stop releases the entry's watcher. It is idempotent.
func (e *forwardEntry) stop() {
	e.doneOnce.Do(func() { close(e.done) })
}

// ForwardedTCPHandler can be enabled by creating a ForwardedTCPHandler and
// adding the HandleSSHRequest callback to the server's RequestHandlers under
// tcpip-forward and cancel-tcpip-forward.
type ForwardedTCPHandler struct {
	// Mutex is embedded, as it was before registrations became structs, so
	// code that locked the handler directly keeps working.
	sync.Mutex
	forwards map[string]*forwardEntry
}

// HandleSSHRequest handles the tcpip-forward and cancel-tcpip-forward
// global requests.
func (h *ForwardedTCPHandler) HandleSSHRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	conn, _ := ctx.Value(ContextKeyConn).(*gossh.ServerConn)

	switch req.Type {
	case "tcpip-forward":
		return h.handleForward(ctx, srv, conn, req)
	case "cancel-tcpip-forward":
		return h.handleCancel(ctx, srv, conn, req)
	default:
		return false, nil
	}
}

func (h *ForwardedTCPHandler) handleForward(ctx Context, srv *Server, conn *gossh.ServerConn, req *gossh.Request) (bool, []byte) {
	var reqPayload remoteForwardRequest
	if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		slog.Warn("ssh: failed to parse tcpip-forward request", "err", err)
		return false, []byte{}
	}
	if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
		return false, []byte("port forwarding is disabled")
	}
	// Refuse new registrations once the server starts draining. The server
	// tracks forwarding listeners, and that tracking rejects the registration
	// under the same lock that Shutdown uses, so a racing request either lands
	// before the drain starts or is turned away here.
	if srv.isShuttingDown() {
		return false, []byte(ErrServerShuttingDown.Error())
	}

	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Warn("ssh: reverse port forward listen failed", "addr", addr, "err", err)
		return false, []byte{}
	}

	_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
	destPort, _ := strconv.Atoi(destPortStr)
	// Use the actual bound port as the key so that port-0 requests don't
	// collide.
	boundAddr := net.JoinHostPort(reqPayload.BindAddr, destPortStr)

	entry := &forwardEntry{
		ln:         ln,
		addr:       boundAddr,
		generation: contextGeneration(ctx),
		owner:      conn,
		close:      closeOnce(ln),
		done:       make(chan struct{}),
	}

	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[string]*forwardEntry)
	}
	if existing := h.forwards[boundAddr]; existing != nil {
		// The binding address is already served by another registration. Only
		// one forward per address may succeed; release the listener we just
		// created without touching the existing one.
		h.Unlock()
		_ = entry.close()
		slog.Warn("ssh: reverse port forward already registered", "addr", boundAddr)
		return false, []byte{}
	}
	// Registering with the server can still fail if the drain began while the
	// listener was being created. In that case this request fails cleanly and
	// leaves every other registration alone.
	if !srv.trackForward(entry, true) {
		h.Unlock()
		_ = entry.close()
		return false, []byte(ErrServerShuttingDown.Error())
	}
	h.forwards[boundAddr] = entry
	h.Unlock()

	h.watchForward(ctx, srv, entry)
	h.acceptForward(srv, conn, entry, reqPayload, destPort)

	return true, gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})
}

// watchForward releases entry when its connection context ends. The cleanup is
// identity-checked, so an old connection's late cancellation cannot close a
// listener that has since been registered at the same address.
func (h *ForwardedTCPHandler) watchForward(ctx Context, srv *Server, entry *forwardEntry) {
	go func() {
		defer recoverAndLog("panic watching reverse forward", nil, nil)
		select {
		case <-ctx.Done():
		case <-entry.done:
			// Already removed by cancel, shutdown, or a failed accept. Return
			// instead of lingering for the rest of the connection's life.
			return
		}
		h.removeForward(srv, entry)
	}()
}

// acceptForward serves the listener until it is closed. Whatever ends the
// accept loop (cancel, shutdown, or a connection-level cleanup), removal is
// again identity-checked.
func (h *ForwardedTCPHandler) acceptForward(srv *Server, conn *gossh.ServerConn, entry *forwardEntry, reqPayload remoteForwardRequest, destPort int) {
	ln := entry.ln
	addr := entry.addr
	go func() {
		defer recoverAndLog("panic accepting reverse forward", nil, nil)
		for {
			c, err := ln.Accept()
			if err != nil {
				slog.Debug("ssh: reverse port forward accept failed", "addr", addr, "err", err)
				break
			}
			originAddr, originPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
			originPort, _ := strconv.Atoi(originPortStr)
			payload := gossh.Marshal(&remoteForwardChannelData{
				DestAddr:   reqPayload.BindAddr,
				DestPort:   uint32(destPort),
				OriginAddr: originAddr,
				OriginPort: uint32(originPort),
			})
			go func() {
				defer recoverAndLog("panic opening forwarded channel", nil, func() {
					_ = c.Close()
				})
				if conn == nil {
					_ = c.Close()
					return
				}
				ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
				if err != nil {
					slog.Warn("ssh: failed to open forwarded channel", "err", err)
					_ = c.Close()
					return
				}
				go gossh.DiscardRequests(reqs)
				closeCh := closeOnce(ch)
				closeConn := closeOnce(c)
				go func() {
					defer recoverAndLog("panic proxying forwarded channel", nil, nil)
					defer closeCh()
					defer closeConn()
					_, _ = io.Copy(ch, c)
				}()
				go func() {
					defer recoverAndLog("panic proxying forwarded channel", nil, nil)
					defer closeCh()
					defer closeConn()
					_, _ = io.Copy(c, ch)
				}()
			}()
		}
		h.removeForward(srv, entry)
	}()
}

// removeForward closes and forgets entry only if it is still the registration
// stored at its address. Every teardown path funnels through here, which makes
// removal idempotent and keeps a late event from an old registration from
// touching a new one.
func (h *ForwardedTCPHandler) removeForward(srv *Server, entry *forwardEntry) {
	h.Lock()
	if cur, ok := h.forwards[entry.addr]; !ok || cur != entry {
		h.Unlock()
		return
	}
	delete(h.forwards, entry.addr)
	h.Unlock()

	entry.stop()
	_ = entry.close()
	srv.trackForward(entry, false)
}

func (h *ForwardedTCPHandler) handleCancel(ctx Context, srv *Server, conn *gossh.ServerConn, req *gossh.Request) (bool, []byte) {
	var reqPayload remoteForwardCancelRequest
	if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
		slog.Warn("ssh: failed to parse cancel-tcpip-forward request", "err", err)
		return false, []byte{}
	}
	addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))

	generation := contextGeneration(ctx)
	h.Lock()
	entry, ok := h.forwards[addr]
	if !ok || entry.generation != generation || (entry.owner != nil && conn != nil && entry.owner != conn) {
		// Not this connection's registration. A late cancel from an old
		// connection must not close a listener another connection now owns.
		h.Unlock()
		return true, nil
	}
	delete(h.forwards, addr)
	h.Unlock()

	entry.stop()
	_ = entry.close()
	srv.trackForward(entry, false)
	return true, nil
}
