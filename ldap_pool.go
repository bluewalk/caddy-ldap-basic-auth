package ldapbasicauth

import (
    "crypto/tls"
    "errors"
    "strings"

    "github.com/caddyserver/caddy/v2"
    "github.com/go-ldap/ldap/v3"
    "go.uber.org/zap"
)

func (m *LDAPBasicAuth) initPool() {
	m.poolOnce.Do(func() {
		m.pool = make(chan *ldap.Conn, m.PoolSize)
		m.anonymousBindSupported = m.supportsAnonymousBind()
		if !m.anonymousBindSupported {
			caddy.Log().Named("ldap_basic_auth").Warn("LDAP server does not support anonymous/unauthenticated bind; connection pooling is disabled")
		}
	})
}

func (m *LDAPBasicAuth) newConn() (*ldap.Conn, error) {
	if m.UseLDAPS {
		serverName := strings.Split(m.LDAPServer, ":")[0]
		tlsConfig := &tls.Config{
			InsecureSkipVerify: m.InsecureSkipVerify,
			ServerName:         serverName,
		}
		return ldap.DialTLS("tcp", m.LDAPServer, tlsConfig)
	}
	return ldap.Dial("tcp", m.LDAPServer)
}

func (m *LDAPBasicAuth) getConn() (*ldap.Conn, error) {
	m.initPool()
	logger := caddy.Log().Named("ldap_basic_auth")
	for {
		select {
		case conn := <-m.pool:
			logger.Debug("Got connection from pool, performing health check")
			// Health check
			if err := conn.Bind("", ""); err != nil && !errors.Is(err, ldap.NewError(ldap.LDAPResultInvalidCredentials, nil)) {
				logger.Debug("Connection from pool failed health check, closing", zap.Error(err))
				conn.Close()
				continue
			}
			logger.Debug("Connection from pool passed health check")
			return conn, nil
		default:
			logger.Debug("No connection available in pool, creating new connection")
			return m.newConn()
		}
	}
}

func (m *LDAPBasicAuth) putConn(conn *ldap.Conn) {
	logger := caddy.Log().Named("ldap_basic_auth")
	if !m.anonymousBindSupported {
		logger.Debug("Anonymous bind not supported, closing connection after use")
		conn.Close()
		return
	}

	if err := conn.Bind("", ""); err != nil {
		logger.Debug("Failed to anonymous-bind before returning to pool, closing connection", zap.Error(err))
		conn.Close()
		return
	}

	select {
	case m.pool <- conn:
		logger.Debug("Returned connection to pool")
	default:
		logger.Debug("Pool is full, closing connection")
		conn.Close()
	}
}

func (m *LDAPBasicAuth) supportsAnonymousBind() bool {
	conn, err := m.newConn()
	if err != nil {
		return false
	}
	defer conn.Close()
	err = conn.Bind("", "")
	return err == nil
}