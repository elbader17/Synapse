package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implementa un rate limiter simple por IP
type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

// NewRateLimiter crea un nuevo rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	// Limpiar entradas antiguas cada minuto
	go rl.cleanup()

	return rl
}

// cleanup limpia las entradas de rate limit antiguas
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, times := range rl.requests {
			var valid []time.Time
			for _, t := range times {
				if now.Sub(t) < rl.window {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.requests, ip)
			} else {
				rl.requests[ip] = valid
			}
		}
		rl.mu.Unlock()
	}
}

// Allow verifica si la request está dentro del límite
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Obtener requests recientes
	var recent []time.Time
	for _, t := range rl.requests[ip] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		rl.requests[ip] = recent
		return false
	}

	rl.requests[ip] = append(recent, now)
	return true
}

// RateLimitMiddleware middleware para Gin
func RateLimitMiddleware(requestsPerMinute int) gin.HandlerFunc {
	rl := NewRateLimiter(requestsPerMinute, time.Minute)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !rl.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Too many requests",
				"retry_after": "1 minute",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
