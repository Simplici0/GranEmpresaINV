package main

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type loginAttempt struct {
	failures    int
	windowStart time.Time
	blockedTill time.Time
}

type loginRateLimiter struct {
	mu          sync.Mutex
	attempts    map[string]loginAttempt
	now         func() time.Time
	maxFailures int
	window      time.Duration
	block       time.Duration
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		attempts:    make(map[string]loginAttempt),
		now:         time.Now,
		maxFailures: 5,
		window:      10 * time.Minute,
		block:       time.Minute,
	}
}

func (l *loginRateLimiter) allow(key string) (bool, time.Duration) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	for candidate, previous := range l.attempts {
		if !previous.blockedTill.After(now) && !previous.windowStart.IsZero() && now.Sub(previous.windowStart) >= l.window {
			delete(l.attempts, candidate)
		}
	}
	attempt, ok := l.attempts[key]
	if !ok || now.Sub(attempt.windowStart) >= l.window {
		l.attempts[key] = loginAttempt{windowStart: now}
		return true, 0
	}
	if attempt.blockedTill.After(now) {
		return false, attempt.blockedTill.Sub(now)
	}
	return true, 0
}

func (l *loginRateLimiter) recordFailure(key string) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	attempt := l.attempts[key]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) >= l.window {
		attempt = loginAttempt{windowStart: now}
	}
	attempt.failures++
	if attempt.failures >= l.maxFailures {
		attempt.blockedTill = now.Add(l.block)
	}
	l.attempts[key] = attempt
}

func (l *loginRateLimiter) recordSuccess(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func loginRateLimitKey(r *http.Request, username string) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	return remote + "\x00" + strings.ToLower(strings.TrimSpace(username))
}

func sessionCookieSecure() bool {
	raw, ok := os.LookupEnv("SESSION_COOKIE_SECURE")
	if !ok || strings.TrimSpace(raw) == "" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			r.URL.Path == "/login" || r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}

		user := userFromContext(r)
		if user == nil || user.CSRFToken == "" {
			http.Error(w, "Solicitud no autorizada.", http.StatusForbidden)
			return
		}

		provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
		if provided == "" {
			provided = strings.TrimSpace(r.FormValue("csrf_token"))
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(user.CSRFToken)) != 1 {
			http.Error(w, "Token CSRF inválido.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func requestLimitsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			limit := int64(2 << 20)
			if r.URL.Path == "/productos/csv" {
				limit = 32 << 20
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.status = status
	w.written = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := generateToken()
		if err != nil {
			requestID = "unknown"
		}
		w.Header().Set("X-Request-ID", requestID)
		started := time.Now()
		wrapped := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(wrapped, r)
		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("http request_id=%s method=%s path=%s status=%d duration=%s", requestID, r.Method, r.URL.Path, status, time.Since(started).Round(time.Millisecond))
	})
}
