package transport

import (
	"sync"

	"google.golang.org/grpc/keepalive"
)

var (
	keepaliveMu     sync.RWMutex
	keepaliveParams *keepalive.ClientParameters
)

// SetKeepaliveParams configures gRPC keepalive for future dials.
func SetKeepaliveParams(params keepalive.ClientParameters) {
	keepaliveMu.Lock()
	keepaliveParams = &params
	keepaliveMu.Unlock()
}

func getKeepaliveParams() (keepalive.ClientParameters, bool) {
	keepaliveMu.RLock()
	params := keepaliveParams
	keepaliveMu.RUnlock()
	if params == nil {
		return keepalive.ClientParameters{}, false
	}
	return *params, true
}
