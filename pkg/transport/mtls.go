package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/sliverarmory/sliver-crackstation/pkg/operatorconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

const (
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024

	// ClientMaxReceiveMessageSize is the max gRPC receive size, matching Sliver.
	ClientMaxReceiveMessageSize = (2 * gb) - 1

	defaultTimeout = 10 * time.Second
)

type connectionCloser interface {
	Close() error
}

type tokenAuth struct {
	token string
}

var connClosers sync.Map // *grpc.ClientConn -> connectionCloser

// GetRequestMetadata returns the auth header for each RPC request.
func (t tokenAuth) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": "Bearer " + t.token,
	}, nil
}

// RequireTransportSecurity declares that the token must only be sent over TLS.
func (tokenAuth) RequireTransportSecurity() bool {
	return true
}

// MTLSConnect connects to a Sliver multiplayer endpoint using direct mTLS or,
// when configured, a WireGuard-wrapped mTLS transport.
func MTLSConnect(config *operatorconfig.ClientConfig) (rpcpb.SliverRPCClient, *grpc.ClientConn, error) {
	if shouldUseWireGuard(config) {
		return wireGuardMTLSConnect(config)
	}
	return directMTLSConnect(config)
}

// CloseConnection closes a gRPC client connection and any transport-specific
// resources attached to it.
func CloseConnection(conn *grpc.ClientConn) error {
	if conn == nil {
		return nil
	}

	var errs []error
	if closer := unregisterConnCloser(conn); closer != nil {
		errs = append(errs, closer.Close())
	}
	errs = append(errs, conn.Close())
	return errors.Join(errs...)
}

func shouldUseWireGuard(config *operatorconfig.ClientConfig) bool {
	if config == nil || config.WG == nil {
		return false
	}
	return true
}

func directMTLSConnect(config *operatorconfig.ClientConfig) (rpcpb.SliverRPCClient, *grpc.ClientConn, error) {
	options, err := newMTLSDialOptions(config)
	if err != nil {
		return nil, nil, err
	}
	return dialRPCClient(fmt.Sprintf("%s:%d", config.LHost, config.LPort), options, nil)
}

func newMTLSDialOptions(config *operatorconfig.ClientConfig) ([]grpc.DialOption, error) {
	tlsConfig, err := getTLSConfig(config.CACertificate, config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}

	options := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(credentials.PerRPCCredentials(tokenAuth{token: config.Token})),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(ClientMaxReceiveMessageSize)),
	}
	if kp, ok := getKeepaliveParams(); ok {
		options = append(options, grpc.WithKeepaliveParams(kp))
	}
	return options, nil
}

func dialRPCClient(target string, options []grpc.DialOption, closer connectionCloser) (rpcpb.SliverRPCClient, *grpc.ClientConn, error) {
	connection, err := grpc.NewClient(target, options...)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, err
	}
	registerConnCloser(connection, closer)

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	for {
		state := connection.GetState()
		if state == connectivity.Idle {
			connection.Connect()
		}
		if state == connectivity.Ready {
			break
		}
		if !connection.WaitForStateChange(ctx, state) {
			_ = CloseConnection(connection)
			return nil, nil, ctx.Err()
		}
	}

	return rpcpb.NewSliverRPCClient(connection), connection, nil
}

func registerConnCloser(conn *grpc.ClientConn, closer connectionCloser) {
	if conn == nil || closer == nil {
		return
	}
	connClosers.Store(conn, closer)
}

func unregisterConnCloser(conn *grpc.ClientConn) connectionCloser {
	if conn == nil {
		return nil
	}
	if closer, ok := connClosers.LoadAndDelete(conn); ok {
		return closer.(connectionCloser)
	}
	return nil
}

func getTLSConfig(caCertificate string, certificate string, privateKey string) (*tls.Config, error) {
	certPEM, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		log.Printf("Cannot parse client certificate: %v", err)
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(caCertificate))

	return &tls.Config{
		Certificates:       []tls.Certificate{certPEM},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return rootOnlyVerifyCertificate(caCertificate, rawCerts)
		},
	}, nil
}

func rootOnlyVerifyCertificate(caCertificate string, rawCerts [][]byte) error {
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(caCertificate)); !ok {
		log.Printf("Failed to parse root certificate")
		os.Exit(3)
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		return err
	}

	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		log.Printf("Failed to verify certificate: %v", err)
		return err
	}
	return nil
}
