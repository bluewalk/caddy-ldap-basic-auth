package ldapbasicauth

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(LDAPBasicAuth{})
	httpcaddyfile.RegisterHandlerDirective("ldap_basic_auth", parseCaddyfileHandler)
}

type LDAPBasicAuth struct {
	LDAPServer          string `json:"ldap_server"`
	BaseDN              string `json:"base_dn"`
	UserAttr            string `json:"user_attr"`
	GroupMembershipDN   string `json:"group_membership_dn"`
	GroupMembershipAttr string `json:"group_membership_attr,omitempty"`
	UseLDAPS            bool   `json:"use_ldaps,omitempty"`
	InsecureSkipVerify  bool   `json:"insecure_skip_verify,omitempty"`
	PoolSize            int    `json:"pool_size,omitempty"`

	RateLimitMaxAttempts     int           `json:"rate_limit_max_attempts,omitempty"`
	RateLimitWindowSeconds   int           `json:"rate_limit_window_seconds,omitempty"`
	RateLimitLockoutSeconds  int           `json:"rate_limit_lockout_seconds,omitempty"`

	poolOnce sync.Once
	pool     chan *ldap.Conn

	anonymousBindSupported bool
}

var (
	_ caddyhttp.MiddlewareHandler = (*LDAPBasicAuth)(nil)
	_ caddyfile.Unmarshaler       = (*LDAPBasicAuth)(nil)
)

func (LDAPBasicAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ldap_basic_auth",
		New: func() caddy.Module { return new(LDAPBasicAuth) },
	}
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(LDAPBasicAuth)
	err := m.UnmarshalCaddyfile(h.Dispenser)

	return m, err
}

func (m *LDAPBasicAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "ldap_server":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.LDAPServer = d.Val()
			case "base_dn":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BaseDN = d.Val()
			case "user_attr":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.UserAttr = d.Val()
			case "group_membership_dn":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.GroupMembershipDN = d.Val()
			case "group_membership_attr":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.GroupMembershipAttr = d.Val()
			case "use_ldaps":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.UseLDAPS = true
			case "insecure_skip_verify":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.InsecureSkipVerify = true
			case "pool_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var size int
				_, err := fmt.Sscanf(d.Val(), "%d", &size)
				if err != nil || size < 1 {
					return d.Errf("invalid pool_size value: %s", d.Val())
				}
				m.PoolSize = size
			case "rate_limit_max_attempts":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				_, err := fmt.Sscanf(d.Val(), "%d", &v)
				if err != nil || v < 1 {
					return d.Errf("invalid rate_limit_max_attempts: %s", d.Val())
				}
				m.RateLimitMaxAttempts = v
			case "rate_limit_window_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				_, err := fmt.Sscanf(d.Val(), "%d", &v)
				if err != nil || v < 1 {
					return d.Errf("invalid rate_limit_window_seconds: %s", d.Val())
				}
				m.RateLimitWindowSeconds = v
			case "rate_limit_lockout_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				_, err := fmt.Sscanf(d.Val(), "%d", &v)
				if err != nil || v < 1 {
					return d.Errf("invalid rate_limit_lockout_seconds: %s", d.Val())
				}
				m.RateLimitLockoutSeconds = v
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	if m.GroupMembershipAttr == "" {
		m.GroupMembershipAttr = "member"
	}
	if m.PoolSize == 0 {
		m.PoolSize = 5
	}
	if m.RateLimitMaxAttempts == 0 {
		m.RateLimitMaxAttempts = 5
	}
	if m.RateLimitWindowSeconds == 0 {
		m.RateLimitWindowSeconds = 60
	}
	if m.RateLimitLockoutSeconds == 0 {
		m.RateLimitLockoutSeconds = 300
	}

	return nil
}

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
				continue // try next or create new
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

var clientIPHeaders = []string{
	"CF-Connecting-IP",
	"X-Forwarded-For",
	"X-Real-IP",
}

func getClientIP(r *http.Request) string {
	for _, header := range clientIPHeaders {
		if value := r.Header.Get(header); value != "" {
			parts := strings.Split(value, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type rateLimitInfo struct {
	Attempts    int
	FirstFailed time.Time
	LockedUntil time.Time
}

var rateLimitMap sync.Map

func (m *LDAPBasicAuth) checkRateLimit(ip string) (locked bool, until time.Time) {
	now := time.Now()
	val, _ := rateLimitMap.LoadOrStore(ip, &rateLimitInfo{})
	info := val.(*rateLimitInfo)

	if info.LockedUntil.After(now) {
		return true, info.LockedUntil
	}
	window := time.Duration(m.RateLimitWindowSeconds) * time.Second
	if now.Sub(info.FirstFailed) > window {
		info.Attempts = 0
		info.FirstFailed = now
	}
	return false, time.Time{}
}

func (m *LDAPBasicAuth) registerFailedAttempt(ip string) {
	now := time.Now()
	val, _ := rateLimitMap.LoadOrStore(ip, &rateLimitInfo{})
	info := val.(*rateLimitInfo)

	window := time.Duration(m.RateLimitWindowSeconds) * time.Second
	lockout := time.Duration(m.RateLimitLockoutSeconds) * time.Second

	if now.Sub(info.FirstFailed) > window {
		info.Attempts = 1
		info.FirstFailed = now
		info.LockedUntil = time.Time{}
	} else {
		info.Attempts++
		if info.Attempts >= m.RateLimitMaxAttempts {
			info.LockedUntil = now.Add(lockout)
		}
	}
}

func (m *LDAPBasicAuth) resetRateLimit(ip string) {
	rateLimitMap.Delete(ip)
}

func (m *LDAPBasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logger := caddy.Log().Named("ldap_basic_auth")
	auth := r.Header.Get("Authorization")
	remote_addr := getClientIP(r)

	if !strings.HasPrefix(auth, "Basic ") {
		logger.Warn(
			"No or invalid Authorization header",
			zap.String("remote_addr", remote_addr),
			zap.String("host", r.Host),
			zap.String("path", r.URL.Path),
		)

		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		w.WriteHeader(http.StatusUnauthorized)

		return nil
	}

    if locked, until := m.checkRateLimit(remote_addr); locked {
		logger.Warn("Too many failed attempts, IP is temporarily locked", zap.String("remote_addr", remote_addr), zap.Time("locked_until", until))
		
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(until.Sub(time.Now()).Seconds())))
		w.WriteHeader(http.StatusTooManyRequests)

        return nil
    }

	payload, perr := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if perr != nil {
		logger.Warn("Base64 decode failed", zap.String("remote_addr", remote_addr))

		w.WriteHeader(http.StatusUnauthorized)
		m.registerFailedAttempt(remote_addr)

		return nil
	}
	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		logger.Warn("Malformed credentials", zap.String("remote_addr", remote_addr))

		w.WriteHeader(http.StatusUnauthorized)
		m.registerFailedAttempt(remote_addr)

		return nil
	}
	username, password := pair[0], pair[1]
	if strings.ContainsAny(username, ",=+<>#;\"\\") || strings.TrimSpace(username) != username || strings.ContainsAny(username, " \t\r\n") {
		logger.Warn("Username contains invalid/suspicious or whitespace characters", zap.String("user", username), zap.String("remote_addr", remote_addr))
		
		w.WriteHeader(http.StatusUnauthorized)
		m.registerFailedAttempt(remote_addr)

		return nil
	}
	// Restrict usernames to ASCII only
	for _, char := range username {
		if char > 127 {
			logger.Warn("Username contains non-ASCII characters", zap.String("user", username), zap.String("remote_addr", remote_addr))
			w.WriteHeader(http.StatusUnauthorized)
			m.registerFailedAttempt(remote_addr)
			return nil
		}
	}
	logger.Info("Attempting authentication", zap.String("user", username), zap.String("remote_addr", remote_addr))

	if m.InsecureSkipVerify {
		logger.Warn("TLS certificate verification is disabled! This is insecure and should not be used in production.")
	}

	// Use connection pool
	var l *ldap.Conn
	var err error
	l, err = m.getConn()
	if err != nil {
		logger.Error("LDAP connection failed", zap.String("user", username), zap.Error(err))

		w.WriteHeader(http.StatusUnauthorized)
		m.registerFailedAttempt(remote_addr)

		return nil
	}
	if l == nil {
		logger.Error("LDAP connection returned nil")

		w.WriteHeader(http.StatusUnauthorized)
		m.registerFailedAttempt(remote_addr)

		return nil
	}
	defer m.putConn(l)

	userDN := fmt.Sprintf("%s=%s,%s", m.UserAttr, ldap.EscapeDN(username), m.BaseDN)
	err = l.Bind(userDN, password)
	if err != nil {
		logger.Warn("LDAP bind failed", zap.String("user", username), zap.Error(err))
		m.registerFailedAttempt(remote_addr)
		
		time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)

		return nil
	}

	logger.Debug("LDAP bind successful", zap.String("user", username))

	// Check group membership
	if m.GroupMembershipDN != "" {
		groupFilter := fmt.Sprintf("(%s=%s)", m.GroupMembershipAttr, ldap.EscapeFilter(userDN))
		logger.Debug("Preparing LDAP group membership search", zap.String("base", m.BaseDN), zap.String("filter", groupFilter), zap.String("userDN", userDN))
		groupSearch := ldap.NewSearchRequest(
			m.BaseDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			groupFilter,
			[]string{"dn"},
			nil,
		)
		groupResult, groupErr := l.Search(groupSearch)
		if groupErr != nil {
			logger.Warn("LDAP group search error", zap.String("user", username), zap.Error(groupErr))
		}
		entryCount := 0
		if groupResult != nil {
			entryCount = len(groupResult.Entries)
		}
		logger.Debug("LDAP group search result", zap.Int("entry_count", entryCount))
		if groupErr != nil || entryCount == 0 {
			logger.Info("User is not a member of group", zap.String("user", username), zap.String("group", m.GroupMembershipDN), zap.String("filter", groupFilter))
			// Add a small random delay to mitigate timing attacks
			time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
			w.WriteHeader(http.StatusUnauthorized)
			m.registerFailedAttempt(remote_addr)
			return nil
		}
		logger.Debug("User is a member of group", zap.String("user", username), zap.String("group", m.GroupMembershipDN), zap.String("filter", groupFilter))
	}

	m.resetRateLimit(remote_addr)
	logger.Info("Authentication successful", zap.String("user", username), zap.String("remote_addr", remote_addr))

	return next.ServeHTTP(w, r)
}