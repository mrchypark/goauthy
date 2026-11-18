package upstreamprovider

import (
	"net/http"
	"time"

	"github.com/mrchypark/goauthy/internal/netsec"
)

var errUnsafeUpstreamHost = netsec.ErrUnsafeHost

func newSafeHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return netsec.NewSafeHTTPClient(timeout, allowPrivate, nil)
}
