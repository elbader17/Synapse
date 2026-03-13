package entities

import (
	"time"
)

// ============================================================
// USER CON 2FA ENHANCED
// ============================================================

// User representa un usuario del sistema con soporte 2FA
type User struct {
	ID           string  `json:"id"`
	Email        string  `json:"email"`
	PasswordHash string  `json:"-"` // Nunca exponer en JSON
	Role         string  `json:"role"`
	FullName     string  `json:"full_name"`
	Department   *string `json:"department,omitempty"`
	License      *string `json:"license,omitempty"`

	// 2FA Configuration
	TwoFactorEnabled bool     `json:"two_factor_enabled"`
	TwoFactorSecret  string   `json:"-"`                 // Cifrado - nunca exponer
	TwoFactorMethod  string   `json:"two_factor_method"` // "totp", "email", "sms"
	BackupCodes      []string `json:"-"`                 // Hash de códigos de respaldo

	// Security
	IsActive            bool       `json:"is_active"`
	IsLocked            bool       `json:"is_locked"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LockoutUntil        *time.Time `json:"lockout_until,omitempty"`
	LastFailedLogin     *time.Time `json:"last_failed_login,omitempty"`

	// Session tracking
	LastLogin       *time.Time `json:"last_login,omitempty"`
	LastLoginIP     *string    `json:"last_login_ip,omitempty"`
	LastLoginDevice *string    `json:"last_login_device,omitempty"`

	// Password security
	PasswordChangedAt  *time.Time `json:"password_changed_at,omitempty"`
	MustChangePassword bool       `json:"must_change_password"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TwoFactorMethod tipos soportados
const (
	TwoFactorMethodNone  = ""
	TwoFactorMethodTOTP  = "totp"
	TwoFactorMethodEmail = "email"
	TwoFactorMethodSMS   = "sms"
)

// BackupCode representa un código de respaldo
type BackupCode struct {
	Code      string     `json:"code"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// LoginSession representa una sesión activa
type LoginSession struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	Token             string    `json:"token"`
	RefreshToken      string    `json:"refresh_token"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	DeviceInfo        string    `json:"device_info"`
	TwoFactorVerified bool      `json:"two_factor_verified"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivity      time.Time `json:"last_activity"`
}

// ============================================================
// AUTHENTICATION DTOs
// ============================================================

// LoginRequest - Paso 1: credenciales
type LoginRequest struct {
	Email      string `json:"email" binding:"required,email"`
	Password   string `json:"password" binding:"required"`
	DeviceInfo string `json:"device_info,omitempty"` // Información del dispositivo
}

// LoginResponseStep1 - Respuesta si se requiere 2FA
type LoginResponseStep1 struct {
	RequireTwoFactor bool   `json:"require_two_factor"`
	TwoFactorMethod  string `json:"two_factor_method"` // "totp", "email"
	TempToken        string `json:"temp_token"`        // Token temporal para step 2
	ExpiresIn        int    `json:"expires_in"`        // segundos
	Message          string `json:"message"`
}

// LoginVerify2FARequest - Paso 2: verificar 2FA
type LoginVerify2FARequest struct {
	TempToken string `json:"temp_token" binding:"required"`
	Code      string `json:"code" binding:"required"` // TOTP code o backup code
}

// LoginVerifyBackupCodeRequest - Verificar con código de respaldo
type LoginVerifyBackupCodeRequest struct {
	TempToken  string `json:"temp_token" binding:"required"`
	BackupCode string `json:"backup_code" binding:"required"`
}

// LoginResponseSuccess - Respuesta final de login exitoso
type LoginResponseSuccess struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	ExpiresIn       int64  `json:"expires_in"`
	User            User   `json:"user"`
	PasswordExpired bool   `json:"password_expired"`
}

// Enable2FARequest - Habilitar 2FA
type Enable2FARequest struct {
	Password string `json:"password" binding:"required"`
	Method   string `json:"method" binding:"required,oneof=totp email"`
}

// Enable2FAResponse - Respuesta al habilitar 2FA
type Enable2FAResponse struct {
	Secret       string   `json:"secret"`        // Para TOTP: código QR
	SecretBase32 string   `json:"secret_base32"` // Para usar con authenticator
	QRCodeURL    string   `json:"qr_code_url"`   // URL de la imagen QR
	BackupCodes  []string `json:"backup_codes"`  // Códigos de respaldo (solo una vez)
	Message      string   `json:"message"`
}

// Verify2FASetupRequest - Verificar configuración inicial de 2FA
type Verify2FASetupRequest struct {
	Code string `json:"code" binding:"required"`
}

// Disable2FARequest - Deshabilitar 2FA
type Disable2FARequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"` // TOTP o backup code
}

// ChangePasswordRequest - Cambiar contraseña
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=12"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// RefreshTokenRequest - Renovar token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest - Cerrar sesión
type LogoutRequest struct {
	AllSessions bool `json:"all_sessions"` // Cerrar todas las sesiones
}

// PasswordRequirements requisitos de contraseña segura
type PasswordRequirements struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireNumber  bool `json:"require_number"`
	RequireSpecial bool `json:"require_special"`
	MaxAgeDays     int  `json:"max_age_days"`
}

// GetPasswordRequirements retorna los requisitos de contraseña
func GetPasswordRequirements() PasswordRequirements {
	return PasswordRequirements{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
		MaxAgeDays:     90,
	}
}

// ============================================================
// MEDICAL RECORD (from original)
// ============================================================

// MedicalRecord representa un registro clínico del paciente
type MedicalRecord struct {
	ID               string     `json:"id"`
	PatientID        string     `json:"patient_id"`
	RecordType       string     `json:"record_type"`
	EncryptedContent string     `json:"-"`
	ProviderID       string     `json:"provider_id"`
	FacilityID       string     `json:"facility_id"`
	VisitDate        time.Time  `json:"visit_date"`
	IsConfidential   bool       `json:"is_confidential"`
	IsActive         bool       `json:"is_active"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

// CreateMedicalRecordRequest request para crear registro
type CreateMedicalRecordRequest struct {
	PatientID      string `json:"patient_id" binding:"required"`
	RecordType     string `json:"record_type" binding:"required,oneof=consultation diagnosis prescription lab_result procedure imaging note"`
	Content        string `json:"content" binding:"required"`
	VisitDate      string `json:"visit_date" binding:"required"`
	IsConfidential bool   `json:"is_confidential"`
}

// TokenClaims JWT claims
type TokenClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}
