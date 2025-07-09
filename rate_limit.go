package ldapbasicauth

import (
    "sync"
    "time"
)

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