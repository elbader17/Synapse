package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"medical-records-manager/internal/domain/entities"
	"medical-records-manager/internal/infrastructure/auth"
	"medical-records-manager/internal/infrastructure/logging"
)

// AuthHandler maneja las solicitudes de autenticación
type AuthHandler struct {
	authService *auth.AuthService
}

// NewAuthHandler crea un nuevo AuthHandler
func NewAuthHandler(authService *auth.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Login - Paso 1: Verificar credenciales
// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req entities.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Obtener IP y user agent
	ip := logging.GetClientIP(c)
	userAgent := c.Request.UserAgent()
	deviceInfo := req.DeviceInfo
	if deviceInfo == "" {
		deviceInfo = c.Request.Header.Get("User-Agent")
	}

	// Verificar credenciales
	response, user, err := h.authService.Step1VerifyCredentials(
		req.Email,
		req.Password,
		ip,
		userAgent,
		deviceInfo,
	)

	if err != nil {
		// Determinar código de estado
		status := http.StatusUnauthorized
		message := "Invalid credentials"

		switch err {
		case auth.ErrAccountInactive:
			status = http.StatusForbidden
			message = "Account is inactive"
		case auth.ErrAccountLocked:
			status = http.StatusLocked
			message = err.Error()
		}

		c.JSON(status, gin.H{
			"error": message,
			"code":  "AUTH_FAILED",
		})
		return
	}

	// Si no requiere 2FA, devolver tokens directamente
	if user != nil && response == nil {
		// Generar tokens (esto debería ser parte del servicio)
		// Por ahora, devolver respuesta de éxito simulada
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"data": gin.H{
				"user": gin.H{
					"id":        user.ID,
					"email":     user.Email,
					"role":      user.Role,
					"full_name": user.FullName,
				},
			},
		})
		return
	}

	// Requiere 2FA
	c.JSON(http.StatusOK, gin.H{
		"require_two_factor": response.RequireTwoFactor,
		"two_factor_method":  response.TwoFactorMethod,
		"temp_token":         response.TempToken,
		"expires_in":         response.ExpiresIn,
		"message":            response.Message,
	})
}

// Verify2FA - Paso 2: Verificar código 2FA
// POST /api/v1/auth/verify-2fa
func (h *AuthHandler) Verify2FA(c *gin.Context) {
	var req entities.LoginVerify2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Obtener IP y user agent
	ip := logging.GetClientIP(c)
	userAgent := c.Request.UserAgent()

	// Verificar código 2FA
	response, err := h.authService.Step2Verify2FA(
		req.TempToken,
		req.Code,
		ip,
		userAgent,
	)

	if err != nil {
		status := http.StatusUnauthorized
		message := "Invalid 2FA code"

		switch err {
		case auth.ErrInvalidTempToken:
			message = "Session expired, please login again"
		case auth.ErrInvalid2FACode:
			message = "Invalid or expired 2FA code"
		}

		c.JSON(status, gin.H{
			"error": message,
			"code":  "2FA_FAILED",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":     response.AccessToken,
		"refresh_token":    response.RefreshToken,
		"expires_in":       response.ExpiresIn,
		"password_expired": response.PasswordExpired,
		"user": gin.H{
			"id":                 response.User.ID,
			"email":              response.User.Email,
			"role":               response.User.Role,
			"full_name":          response.User.FullName,
			"two_factor_enabled": response.User.TwoFactorEnabled,
		},
	})
}

// Setup2FA - Generar configuración inicial de 2FA
// POST /api/v1/auth/2fa/setup
func (h *AuthHandler) Setup2FA(c *gin.Context) {
	// Obtener user ID del contexto (del middleware JWT)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req entities.Enable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Generar configuración 2FA
	response, err := h.authService.Generate2FASetup(
		userID.(string),
		req.Password,
		req.Method,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":        response.Secret,
		"secret_base32": response.SecretBase32,
		"qr_code_url":   response.QRCodeURL,
		"backup_codes":  response.BackupCodes, // Solo se muestra una vez
		"message":       response.Message,
	})
}

// Verify2FASetup - Verificar y habilitar 2FA
// POST /api/v1/auth/2fa/verify
func (h *AuthHandler) Verify2FASetup(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req entities.Verify2FASetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Obtener secreto temporal de la sesión o DB
	// Por simplicidad, usar un secret fijo (en producción, guardar en sesión)
	secret := c.GetHeader("X-2FA-Secret")
	if secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "2FA secret not found, please call setup first",
		})
		return
	}

	err := h.authService.VerifyAndEnable2FA(userID.(string), secret, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid verification code",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":            "2FA enabled successfully",
		"two_factor_enabled": true,
	})
}

// Disable2FA - Deshabilitar 2FA
// POST /api/v1/auth/2fa/disable
func (h *AuthHandler) Disable2FA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req entities.Disable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	err := h.authService.Disable2FA(userID.(string), req.Password, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to disable 2FA",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":            "2FA disabled successfully",
		"two_factor_enabled": false,
	})
}

// ChangePassword - Cambiar contraseña
// POST /api/v1/auth/change-password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req entities.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Verificar que las contraseñas coincidan
	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Passwords do not match",
		})
		return
	}

	// Validar requisitos de contraseña
	if err := h.authService.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Password does not meet requirements",
			"details": err.Error(),
		})
		return
	}

	// Cambiar contraseña
	err := h.authService.ChangePassword(userID.(string), req.CurrentPassword, req.NewPassword)
	if err != nil {
		status := http.StatusBadRequest
		message := "Failed to change password"

		switch err {
		case auth.ErrInvalidCredentials:
			message = "Current password is incorrect"
		}

		c.JSON(status, gin.H{
			"error": message,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// RefreshToken - Renovar token de acceso
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req entities.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// TODO: Implementar refresh token
	// Por ahora, devolver error
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "Refresh token not implemented yet",
	})
}

// Logout - Cerrar sesión
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	_, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req entities.LogoutRequest
	c.ShouldBindJSON(&req)

	// TODO: Invalidar tokens
	// Por ahora, simplemente responder éxito

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// GetPasswordRequirements - Obtener requisitos de contraseña
// GET /api/v1/auth/password-requirements
func (h *AuthHandler) GetPasswordRequirements(c *gin.Context) {
	req := entities.GetPasswordRequirements()
	c.JSON(http.StatusOK, gin.H{
		"min_length":      req.MinLength,
		"require_upper":   req.RequireUpper,
		"require_lower":   req.RequireLower,
		"require_number":  req.RequireNumber,
		"require_special": req.RequireSpecial,
		"max_age_days":    req.MaxAgeDays,
	})
}
