package ldapbasicauth

import (
    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
    "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
    "github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
    caddy.RegisterModule(LDAPBasicAuth{})
    httpcaddyfile.RegisterHandlerDirective("ldap_basic_auth", parseCaddyfileHandler)
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