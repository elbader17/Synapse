package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders middleware adds security headers to prevent common attacks
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// XSS Protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Strict Transport Security (HSTS) - only in production
		// c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Content Security Policy (CSP)
		c.Header("Content-Security-Policy", "default-src 'self'")

		// Referrer Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		c.Next()
	}
}

// RequireAuth middleware requires authentication
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Verify Bearer token format
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		// Continue to next middleware/handler
		c.Next()
	}
}

// RequireRole middleware requires a specific role
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user role from context (set by JWT middleware)
		role, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User role not found",
			})
			c.Abort()
			return
		}

		// Check if user has required role
		userRole := role.(string)
		for _, r := range roles {
			if userRole == r {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error":          "Insufficient permissions",
			"required_roles": roles,
		})
		c.Abort()
	}
}
