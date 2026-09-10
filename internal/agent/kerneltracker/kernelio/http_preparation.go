package kernelio

import (
	"context"
	"os"
)

// MaxHTTPPreparationFiles bounds descriptors adopted by one worker request.
const MaxHTTPPreparationFiles = 32

// HTTPFilePreparer is implemented by the Linux HTTP worker boundary. It takes
// ownership of every file on entry, including rejection/cancellation. Callers
// must not use or close these descriptors after calling PrepareHTTPFiles.
// The final FD is an unread /proc/PID/cgroup file, resolved in the Agent view.
type HTTPFilePreparer interface {
	PrepareHTTPFiles(context.Context, []*os.File, string, *os.File) error
}
