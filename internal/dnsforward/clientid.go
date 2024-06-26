package dnsforward

import (
	"crypto/tls"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/quic-go/quic-go"
)

// ValidateClientID returns an error if id is not a valid ClientID.
//
// Keep in sync with [client.ValidateClientID].
func ValidateClientID(id string) (err error) {
	err = netutil.ValidateHostnameLabel(id)
	if err != nil {
		// Replace the domain name label wrapper with our own.
		return fmt.Errorf("invalid clientid %q: %w", id, errors.Unwrap(err))
	}

	return nil
}

// clientIDFromClientServerName extracts and validates a ClientID.  hostSrvName
// is the server name of the host.  cliSrvName is the server name as sent by the
// client.  When strict is true, and client and host server name don't match,
// clientIDFromClientServerName will return an error.
func clientIDFromClientServerName(
	hostSrvNames []string,
	cliSrvName string,
	strict bool,
) (clientID string, err error) {
	if slices.Contains(hostSrvNames, cliSrvName) {
		return "", nil
	}
	clientID = ""

	for _, hostSrvName := range hostSrvNames {
		if !netutil.IsImmediateSubdomain(cliSrvName, hostSrvName) {
			if !strict {
				err = nil
			} else {
				err = fmt.Errorf(
					"client server name %q doesn't match host server name %q",
					cliSrvName,
					hostSrvName,
				)
			}
		} else {
			clientID = cliSrvName[:len(cliSrvName)-len(hostSrvName)-1]
			err = ValidateClientID(clientID)
		}
	}

	return strings.ToLower(clientID), err
}

// clientIDFromDNSContextHTTPS extracts the client's ID from the path of the
// client's DNS-over-HTTPS request.
func clientIDFromDNSContextHTTPS(pctx *proxy.DNSContext) (clientID string, err error) {
	r := pctx.HTTPRequest
	if r == nil {
		return "", fmt.Errorf(
			"proxy ctx http request of proto %s is nil",
			pctx.Proto,
		)
	}

	origPath := r.URL.Path
	parts := strings.Split(path.Clean(origPath), "/")
	if parts[0] == "" {
		parts = parts[1:]
	}

	if len(parts) == 0 || parts[0] != "dns-query" {
		return "", fmt.Errorf("clientid check: invalid path %q", origPath)
	}

	switch len(parts) {
	case 1:
		// Just /dns-query, no ClientID.
		return "", nil
	case 2:
		clientID = parts[1]
	default:
		return "", fmt.Errorf("clientid check: invalid path %q: extra parts", origPath)
	}

	err = ValidateClientID(clientID)
	if err != nil {
		return "", fmt.Errorf("clientid check: %w", err)
	}

	return strings.ToLower(clientID), nil
}

// tlsConn is a narrow interface for *tls.Conn to simplify testing.
type tlsConn interface {
	ConnectionState() (cs tls.ConnectionState)
}

// quicConnection is a narrow interface for quic.Connection to simplify testing.
type quicConnection interface {
	ConnectionState() (cs quic.ConnectionState)
}

// clientServerName returns the TLS server name based on the protocol.  For
// DNS-over-HTTPS requests, it will return the hostname part of the Host header
// if there is one.
func clientServerName(pctx *proxy.DNSContext, proto proxy.Proto) (srvName string, err error) {
	from := "tls conn"

	switch proto {
	case proxy.ProtoHTTPS:
		r := pctx.HTTPRequest
		if connState := r.TLS; connState != nil {
			srvName = connState.ServerName
		} else if r.Host != "" {
			var host string
			host, err = netutil.SplitHost(r.Host)
			if err != nil {
				return "", fmt.Errorf("parsing host: %w", err)
			}

			srvName = host
			from = "host header"
		}
	case proxy.ProtoQUIC:
		qConn := pctx.QUICConnection
		conn, ok := qConn.(quicConnection)
		if !ok {
			return "", fmt.Errorf("pctx conn of proto %s is %T, want quic.Connection", proto, qConn)
		}

		srvName = conn.ConnectionState().TLS.ServerName
	case proxy.ProtoTLS:
		conn := pctx.Conn
		tc, ok := conn.(tlsConn)
		if !ok {
			return "", fmt.Errorf("pctx conn of proto %s is %T, want *tls.Conn", proto, conn)
		}

		srvName = tc.ConnectionState().ServerName
	}

	log.Debug("dnsforward: got client server name %q from %s", srvName, from)

	return srvName, nil
}
