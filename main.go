package ldapbasicauth

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
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
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	if m.GroupMembershipAttr == "" {
		m.GroupMembershipAttr = "member"
	}

	return nil
}

func (m *LDAPBasicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	logger := caddy.Log().Named("ldap_basic_auth")
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		logger.Warn(
			"No or invalid Authorization header",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
			zap.String("path", r.URL.Path),
		)

		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		w.WriteHeader(http.StatusUnauthorized)

		return nil
	}
	payload, perr := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if perr != nil {
		logger.Warn("Base64 decode failed", zap.String("remote_addr", r.RemoteAddr))
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		logger.Warn("Malformed credentials", zap.String("remote_addr", r.RemoteAddr))
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	username, password := pair[0], pair[1]
	if strings.ContainsAny(username, ",=+<>#;\"\\") || strings.TrimSpace(username) != username || strings.ContainsAny(username, " \t\r\n") {
		logger.Warn("Username contains invalid/suspicious or whitespace characters", zap.String("user", username), zap.String("remote_addr", r.RemoteAddr))
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	// Restrict usernames to ASCII only
	for _, char := range username {
		if char > 127 {
			logger.Warn("Username contains non-ASCII characters", zap.String("user", username), zap.String("remote_addr", r.RemoteAddr))
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		}
	}
	logger.Info("Attempting authentication", zap.String("user", username), zap.String("remote_addr", r.RemoteAddr))

	if m.InsecureSkipVerify {
		logger.Warn("TLS certificate verification is disabled! This is insecure and should not be used in production.")
	}
	var l *ldap.Conn
	var err error
	if m.UseLDAPS {
		serverName := strings.Split(m.LDAPServer, ":")[0]
		tlsConfig := &tls.Config{
			InsecureSkipVerify: m.InsecureSkipVerify,
			ServerName:         serverName,
		}
		l, err = ldap.DialTLS("tcp", m.LDAPServer, tlsConfig)
	} else {
		l, err = ldap.Dial("tcp", m.LDAPServer)
	}

	if err != nil {
		logger.Error("LDAP connection failed", zap.String("user", username), zap.Error(err))
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	if l == nil {
		logger.Error("LDAP connection returned nil")
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}
	defer l.Close()

	userDN := fmt.Sprintf("%s=%s,%s", m.UserAttr, ldap.EscapeDN(username), m.BaseDN)
	err = l.Bind(userDN, password)
	if err != nil {
		logger.Warn("LDAP bind failed", zap.String("user", username), zap.Error(err))
		// Add a small random delay to mitigate timing attacks
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
			m.GroupMembershipDN,
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
			return nil
		}
		logger.Debug("User is a member of group", zap.String("user", username), zap.String("group", m.GroupMembershipDN), zap.String("filter", groupFilter))
	}

	logger.Info("Authentication successful", zap.String("user", username), zap.String("remote_addr", r.RemoteAddr))

	return next.ServeHTTP(w, r)
}
