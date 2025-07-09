package ldapbasicauth

import (
    "encoding/base64"
    "fmt"
    "math/rand"
    "net/http"
    "strings"
    "time"
	"net"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
    "github.com/go-ldap/ldap/v3"
    "go.uber.org/zap"
)

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