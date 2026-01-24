package transport

import (
	"sync"

	"google.golang.org/grpc/keepalive"
)

var (
	keepaliveMu     sync.RWMutex
	keepaliveParams *keepalive.ClientParameters
)

// SetKeepaliveParams configures optional gRPC keepalive settings for MTLSConnect.
func SetKeepaliveParams(params keepalive.ClientParameters) {
	keepaliveMu.Lock()
	defer keepaliveMu.Unlock()
	keepaliveParams = &params
}

func getKeepaliveParams() *keepalive.ClientParameters {
	keepaliveMu.RLock()
	defer keepaliveMu.RUnlock()
	return keepaliveParams
}
