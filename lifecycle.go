package ssh

import (
	"io"
	"sync"
)

// closeOnce returns a function that closes c at most once. Concurrent and
// repeated calls block until the first close completes and all return its
// result.
//
// Teardown in this package runs on several goroutines: the two proxy copy
// loops, the request loop that owns a channel, and the context watcher that
// releases a forward. Each of them may observe an end-of-life event at the
// same time, and a channel or listener that is closed twice reports a spurious
// error (or, worse, tears down a resource a later owner re-registered). A
// closeOnce makes the notification happen exactly once no matter which path
// arrives first.
func closeOnce(c io.Closer) func() error {
	var (
		once sync.Once
		err  error
	)
	return func() error {
		once.Do(func() {
			err = c.Close()
		})
		return err
	}
}
