# Caddy LDAP Basic Auth Plugin

This plugin provides HTTP Basic Authentication for Caddy v2 using an LDAP server for credential validation and group membership checks.

## Features
- Authenticate users against an LDAP/LDAPS server
- Optionally require group membership for access
- Configurable LDAP attributes and connection options
- Structured logging with log levels (debug, info, warn, error)

## Requirements
- Caddy v2.10+
- Go 1.18+
- An accessible LDAP or LDAPS server

## Installation

**Build Caddy with the plugin:**
   
Use [xcaddy](https://github.com/caddyserver/xcaddy) to build Caddy with this plugin:
   
```sh
xcaddy build \
  --with github.com/bluewalk/caddy-ldap-basic-auth
```

**OR**

Use caddy's `add-package` to add this plugin

```sh
caddy add-package github.com/bluewalk/caddy-ldap-basic-auth
```

## Configuration

Add the `ldap_basic_auth` directive to your Caddyfile:

```
route {
    ldap_basic_auth {
        ldap_server            "ldap.example.com:636"
        base_dn                "ou=users,dc=example,dc=com"
        user_attr              "uid"
        group_membership_dn    "cn=admins,ou=groups,dc=example,dc=com"
        group_membership_attr  "member"
        use_ldaps
        insecure_skip_verify   # Optional, only for self-signed certs
    }
    respond "Hello, {http.auth.user}!"
}
```

### Directive Options

| Option                    | Type     | Required | Description                                                                                   |
|---------------------------|----------|----------|-----------------------------------------------------------------------------------------------|
| `ldap_server`             | string   | Yes      | Host:port of your LDAP/LDAPS server.                                                          |
| `base_dn`                 | string   | Yes      | Base DN for user search (e.g., `ou=users,dc=example,dc=com`).                                 |
| `user_attr`               | string   | Yes      | Attribute for username (e.g., `uid` or `sAMAccountName`).                                     |
| `group_membership_dn`     | string   | No       | DN of the group to require membership in.                                                     |
| `group_membership_attr`   | string   | No       | Attribute for group membership (default: `member`).                                           |
| `use_ldaps`               | flag     | No       | Use LDAPS (LDAP over TLS).                                                                    |
| `insecure_skip_verify`    | flag     | No       | Skip TLS verification (not recommended for production).                                       |

## Logging

This plugin uses Caddy's structured logging. You can control log levels and output in your Caddyfile:

```
logging {
    level debug
    logs {
        default {
            level info
            output stdout
        }
        ldap_basic_auth {
            level debug
            output file /var/log/caddy/ldap_auth.log
        }
    }
}
```

## Example

```
:8080 {
    route {
        ldap_basic_auth {
            ldap_server            "ldap.example.com:636"
            base_dn                "ou=users,dc=example,dc=com"
            user_attr              "uid"
            group_membership_dn    "cn=admins,ou=groups,dc=example,dc=com"
            use_ldaps
        }
        respond "Welcome, {http.auth.user}!"
    }
}
```

## Troubleshooting
- Check Caddy logs for authentication and LDAP errors.
- Use `insecure_skip_verify` only for testing with self-signed certificates.
- Ensure your LDAP server is reachable from the Caddy host.

## License
MIT
