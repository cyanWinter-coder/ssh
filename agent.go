package ssh

import (
	"io"
	"net"
	"os"
	"path"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"

	agentTempDir    = "auth-agent"
	agentListenFile = "listener.sock"
)

// contextKeyAgentRequest is an internal context key for storing if the
// client requested agent forwarding.
var contextKeyAgentRequest = &contextKey{"auth-agent-req"}

// SetAgentRequested sets up the session context so that AgentRequested
// returns true.
//
// The request is also recorded on the session currently stored in ctx, so it
// stays scoped to that session: forwarding requested for one session is never
// reported for another session on the same connection, and nothing carries
// over from a previous connection.
func SetAgentRequested(ctx Context) {
	ctx.SetValue(contextKeyAgentRequest, true)
	if sess, ok := ctx.Value(ContextKeySession).(*session); ok {
		sess.Lock()
		sess.agentRequested = true
		sess.Unlock()
	}
}

// AgentRequested returns true if the client requested agent forwarding for
// this session.
//
// For sessions created by this package the answer is strictly session-scoped:
// a request made by an earlier session on the same connection, or by a
// previous connection, is never reported. Contexts are shared by every session
// on a connection, so consulting the context here would reintroduce exactly
// that inheritance. Third-party Session implementations that are not backed by
// this package fall back to the context value.
func AgentRequested(sess Session) bool {
	if sess == nil {
		return false
	}
	if internal, ok := sess.(*session); ok {
		internal.Lock()
		requested := internal.agentRequested
		internal.Unlock()
		return requested
	}
	ctx := sess.Context()
	return ctx != nil && ctx.Value(contextKeyAgentRequest) == true
}

// NewAgentListener sets up a temporary Unix socket that can be communicated
// to the session environment and used for forwarding connections.
func NewAgentListener() (net.Listener, error) {
	dir, err := os.MkdirTemp("", agentTempDir)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path.Join(dir, agentListenFile))
	if err != nil {
		return nil, err
	}
	return l, nil
}

// ForwardAgentConnections takes connections from a listener to proxy into the
// session on the OpenSSH channel for agent connections. It blocks and services
// connections until the listener stop accepting.
func ForwardAgentConnections(l net.Listener, s Session) {
	sshConn := s.Context().Value(ContextKeyConn).(gossh.Conn)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer recoverAndLog("panic forwarding agent connection", nil, nil)
			defer func() { _ = conn.Close() }()
			channel, reqs, err := sshConn.OpenChannel(agentChannelType, nil)
			if err != nil {
				return
			}
			// Both copy loops close the channel when they finish; funnel that
			// through a once so it is closed exactly once.
			closeChannel := closeOnce(channel)
			defer closeChannel()
			go gossh.DiscardRequests(reqs)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				// Done is deferred ahead of the recover so that it runs even
				// if the copy panics. Otherwise the recover would turn a crash
				// into a permanently blocked Wait below, leaking this
				// goroutine along with the socket and the channel.
				defer wg.Done()
				defer closeChannel()
				defer recoverAndLog("panic proxying agent connection", nil, nil)
				_, _ = io.Copy(conn, channel)
				if cw, ok := conn.(*net.UnixConn); ok {
					_ = cw.CloseWrite()
				}
			}()
			go func() {
				defer wg.Done()
				defer closeChannel()
				defer recoverAndLog("panic proxying agent connection", nil, nil)
				_, _ = io.Copy(channel, conn)
				_ = channel.CloseWrite()
			}()
			wg.Wait()
		}(conn)
	}
}
