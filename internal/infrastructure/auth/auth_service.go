package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"medical-records-manager/internal/config"
	"medical-records-manager/internal/domain/entities"
	"medical-records-manager/internal/infrastructure/crypto"
	"medical-records-manager/internal/infrastructure/logging"
	"medical-records-manager/pkg/constants"
)

// ============================================================
// ERRORS
// ============================================================

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAccountLocked       = errors.New("account is locked")
	ErrAccountInactive     = errors.New("account is inactive")
	ErrInvalid2FACode      = errors.New("invalid 2FA code")
	Err2FANotEnabled       = errors.New("2FA is not enabled")
	ErrInvalidTempToken    = errors.New("invalid or expired temp token")
	ErrAllBackupCodesUsed  = errors.New("all backup codes have been used")
	ErrPasswordTooWeak     = errors.New("password does not meet security requirements")
	ErrPasswordMismatch    = errors.New("passwords do not match")
	ErrTokenExpired        = errors.New("token has expired")
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
)

// ============================================================
// TOTP SERVICE - Time-based One-Time Password
// ============================================================

// TOTPService maneja la generación y verificación de códigos TOTP
type TOTPService struct {
	Issuer    string
	Digits    int
	Period    int
	Algorithm string
}

// NewTOTPService crea un nuevo servicio TOTP
func NewTOTPService(issuer string) *TOTPService {
	return &TOTPService{
		Issuer:    issuer,
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
	}
}

// GenerateSecret genera un secreto aleatorio para TOTP
func (s *TOTPService) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateCode genera un código TOTP para el tiempo actual
func (s *TOTPService) GenerateCode(secret string) string {
	return s.GenerateCodeForTime(secret, time.Now().Unix())
}

// GenerateCodeForTime genera un código TOTP para un tiempo específico
func (s *TOTPService) GenerateCodeForTime(secret string, timestamp int64) string {
	counter := timestamp / int64(s.Period)
	return s.generateHOTP(secret, counter)
}

// VerifyCode verifica un código TOTP (acepta el código actual y el anterior por tolerancia de 30s)
func (s *TOTPService) VerifyCode(secret, code string) bool {
	now := time.Now().Unix()

	// Aceptar código actual, anterior y siguiente (tolerancia de 90 segundos)
	for _, t := range []int64{now - 30, now, now + 30} {
		counter := t / int64(s.Period)
		expected := s.generateHOTP(secret, counter)
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func (s *TOTPService) generateHOTP(secret string, counter int64) string {
	// Decodificar secreto
	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}

	// Convertir counter a bytes (big-endian)
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))

	// Calcular HMAC-SHA1
	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	// Obtener código dinámico
	offset := hash[len(hash)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// Generar código de dígitos específicos
	code := truncated % uint32(math.Pow10(s.Digits))
	return fmt.Sprintf("%0*d", s.Digits, code)
}

// GetAuthenticatorURI retorna la URI para configurar el autenticador
func (s *TOTPService) GetAuthenticatorURI(secret, accountName string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		s.Issuer, accountName, secret, s.Issuer, s.Algorithm, s.Digits, s.Period)
}

// ============================================================
// AUTH SERVICE
// ============================================================

// AuthService maneja la autenticación con 2FA
type AuthService struct {
	cfg             *config.Config
	jwtSecret       string
	tokenExpiry     time.Duration
	refreshExpiry   time.Duration
	tempTokenExpiry time.Duration
	totpService     *TOTPService
	encryptor       crypto.EncryptionService
	auditLogger     *logging.AuditLogger
}

// NewAuthService crea un nuevo servicio de autenticación
func NewAuthService(cfg *config.Config, encryptor crypto.EncryptionService, auditLogger *logging.AuditLogger) *AuthService {
	return &AuthService{
		cfg:             cfg,
		jwtSecret:       cfg.JWTSecret,
		tokenExpiry:     cfg.JWTExpiration,
		refreshExpiry:   cfg.RefreshTokenExpiry,
		tempTokenExpiry: 5 * time.Minute,
		totpService:     NewTOTPService("MedicalRecords"),
		encryptor:       encryptor,
		auditLogger:     auditLogger,
	}
}

// ============================================================
// LOGIN FLOW WITH 2FA
// ============================================================

// Step1VerifyCredentials - Paso 1: Verificar credenciales
func (as *AuthService) Step1VerifyCredentials(email, password, ip, userAgent, deviceInfo string) (*entities.LoginResponseStep1, *entities.User, error) {
	// Buscar usuario por email (implementar en repository)
	// user, err := as.userRepo.GetByEmail(email)

	// Por ahora, simulamos la verificación
	// En implementación real, usar repository

	// Simular búsqueda de usuario
	user := as.getMockUser(email)
	if user == nil {
		as.auditLogger.LogFailedAttempt(context.Background(), "", ip, userAgent, "invalid_email", "auth")
		return nil, nil, ErrInvalidCredentials
	}

	// Verificar si la cuenta está activa
	if !user.IsActive {
		return nil, nil, ErrAccountInactive
	}

	// Verificar si la cuenta está bloqueada
	if user.IsLocked && user.LockoutUntil != nil && time.Now().Before(*user.LockoutUntil) {
		remain := time.Until(*user.LockoutUntil)
		return nil, nil, fmt.Errorf("%w: try again in %d minutes", ErrAccountLocked, int(remain.Minutes()))
	}

	// Verificar contraseña
	if !crypto.VerifyPassword(password, user.PasswordHash) {
		// Registrar intento fallido
		as.handleFailedLogin(user, ip, userAgent)
		return nil, nil, ErrInvalidCredentials
	}

	// Credenciales válidas - verificar si requiere 2FA
	if user.TwoFactorEnabled {
		// Generar token temporal para paso 2
		tempToken, err := as.generateTempToken(user.ID, user.Email)
		if err != nil {
			return nil, nil, err
		}

		return &entities.LoginResponseStep1{
			RequireTwoFactor: true,
			TwoFactorMethod:  user.TwoFactorMethod,
			TempToken:        tempToken,
			ExpiresIn:        int(as.tempTokenExpiry.Seconds()),
			Message:          "Please verify your identity with 2FA",
		}, user, nil
	}

	// No tiene 2FA - login directo
	return nil, user, nil
}

// Step2Verify2FA - Paso 2: Verificar código 2FA
func (as *AuthService) Step2Verify2FA(tempToken, code, ip, userAgent string) (*entities.LoginResponseSuccess, error) {
	// Verificar temp token
	claims, err := as.verifyTempToken(tempToken)
	if err != nil {
		return nil, ErrInvalidTempToken
	}

	userID, _ := claims["user_id"].(string)

	// Obtener usuario
	user := as.getMockUserByID(userID)
	if user == nil || !user.IsActive {
		return nil, ErrAccountInactive
	}

	// Verificar código 2FA
	valid := false

	if user.TwoFactorMethod == entities.TwoFactorMethodTOTP {
		// Descifrar secreto
		secret, err := as.encryptor.Decrypt(user.TwoFactorSecret)
		if err != nil {
			return nil, err
		}
		valid = as.totpService.VerifyCode(secret, code)
	} else if user.TwoFactorMethod == entities.TwoFactorMethodEmail {
		// Para email, el código sería enviado por email
		// Implementar verificación de código email
		valid = as.verifyEmailCode(userID, code)
	}

	// Verificar backup codes
	if !valid {
		valid = as.verifyBackupCode(user, code)
	}

	if !valid {
		as.auditLogger.LogFailedAttempt(context.Background(), user.ID, ip, userAgent, "invalid_2fa_code", "auth")
		return nil, ErrInvalid2FACode
	}

	// Generar tokens de sesión
	accessToken, err := as.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := as.generateRefreshToken(user)
	if err != nil {
		return nil, err
	}

	// Actualizar last login
	as.updateSuccessfulLogin(user, ip, userAgent)

	// Registrar en auditoría
	as.auditLogger.Log(logging.AuditEntry{
		Timestamp:    time.Now().UTC(),
		UserID:       user.ID,
		UserRole:     user.Role,
		IP:           ip,
		UserAgent:    userAgent,
		EventType:    constants.EventUserLogin,
		ResourceType: constants.ResourceAuth,
		Action:       constants.ActionLogin,
		Details:      `{"method": "2fa", "device": "unknown"}`,
		Success:      true,
	})

	return &entities.LoginResponseSuccess{
		AccessToken:     accessToken,
		RefreshToken:    refreshToken,
		ExpiresIn:       int64(as.tokenExpiry.Seconds()),
		User:            *user,
		PasswordExpired: user.MustChangePassword,
	}, nil
}

// ============================================================
// 2FA MANAGEMENT
// ============================================================

// Generate2FASetup genera la configuración inicial para 2FA
func (as *AuthService) Generate2FASetup(userID, password, method string) (*entities.Enable2FAResponse, error) {
	user := as.getMockUserByID(userID)
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Verificar contraseña
	if !crypto.VerifyPassword(password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	// Generar secreto TOTP
	secret, err := as.totpService.GenerateSecret()
	if err != nil {
		return nil, err
	}

	// Generar códigos de respaldo
	backupCodes := as.generateBackupCodes()

	// Cifrar secreto
	_, err = as.encryptor.Encrypt(secret)
	if err != nil {
		return nil, err
	}

	// Guardar temporalmente (no habilitado hasta verificar)
	// En implementación real, guardar en DB con flag pending

	// Generar QR code URL
	qrURL := as.totpService.GetAuthenticatorURI(secret, user.Email)

	// Hash de backup codes para almacenar
	hashedCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hashedCodes[i] = crypto.HashToken(code)
	}

	return &entities.Enable2FAResponse{
		Secret:       secret,
		SecretBase32: secret,
		QRCodeURL:    qrURL,
		BackupCodes:  backupCodes,
		Message:      "Save these backup codes in a secure place. They will be needed if you lose access to your authenticator.",
	}, nil
}

// VerifyAndEnable2FA verifica el código y habilita 2FA
func (as *AuthService) VerifyAndEnable2FA(userID, secret, code string) error {
	user := as.getMockUserByID(userID)
	if user == nil {
		return errors.New("user not found")
	}

	// Verificar código TOTP
	if !as.totpService.VerifyCode(secret, code) {
		return ErrInvalid2FACode
	}

	// Habilitar 2FA en usuario (implementar en repository)
	user.TwoFactorEnabled = true
	user.TwoFactorSecret = secret
	user.TwoFactorMethod = entities.TwoFactorMethodTOTP

	return nil
}

// Disable2FA deshabilita 2FA
func (as *AuthService) Disable2FA(userID, password, code string) error {
	user := as.getMockUserByID(userID)
	if user == nil {
		return errors.New("user not found")
	}

	// Verificar contraseña
	if !crypto.VerifyPassword(password, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Verificar código 2FA o backup code
	valid := false

	secret, _ := as.encryptor.Decrypt(user.TwoFactorSecret)
	if as.totpService.VerifyCode(secret, code) {
		valid = true
	}

	if !valid {
		valid = as.verifyBackupCode(user, code)
	}

	if !valid {
		return ErrInvalid2FACode
	}

	// Deshabilitar 2FA
	user.TwoFactorEnabled = false
	user.TwoFactorSecret = ""
	user.TwoFactorMethod = entities.TwoFactorMethodNone
	user.BackupCodes = nil

	return nil
}

// ============================================================
// PASSWORD MANAGEMENT
// ============================================================

// ValidatePassword verifica si la contraseña cumple los requisitos
func (as *AuthService) ValidatePassword(password string) error {
	req := entities.GetPasswordRequirements()

	if len(password) < req.MinLength {
		return fmt.Errorf("password must be at least %d characters", req.MinLength)
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case strings.Contains("!@#$%^&*()_+-=[]{}|;':\",./<>?", string(char)):
			hasSpecial = true
		}
	}

	if req.RequireUpper && !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if req.RequireLower && !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if req.RequireNumber && !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if req.RequireSpecial && !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// ChangePassword cambia la contraseña del usuario
func (as *AuthService) ChangePassword(userID, currentPassword, newPassword string) error {
	user := as.getMockUserByID(userID)
	if user == nil {
		return errors.New("user not found")
	}

	// Verificar contraseña actual
	if !crypto.VerifyPassword(currentPassword, user.PasswordHash) {
		return ErrInvalidCredentials
	}

	// Validar nueva contraseña
	if err := as.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash de nueva contraseña
	newHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = newHash
	user.PasswordChangedAt = newTimePtr(time.Now())
	user.MustChangePassword = false

	return nil
}

// ============================================================
// TOKEN GENERATION
// ============================================================

func (as *AuthService) generateAccessToken(user *entities.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"type":    "access",
		"exp":     time.Now().Add(as.tokenExpiry).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(as.jwtSecret))
}

func (as *AuthService) generateRefreshToken(user *entities.User) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes), nil
}

func (as *AuthService) generateTempToken(userID, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"type":    "temp",
		"exp":     time.Now().Add(as.tempTokenExpiry).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(as.jwtSecret + "_temp"))
}

func (as *AuthService) verifyTempToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(as.jwtSecret + "_temp"), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Verificar tipo de token
		if claims["type"] != "temp" {
			return nil, ErrInvalidTempToken
		}
		return claims, nil
	}

	return nil, ErrInvalidTempToken
}

// ============================================================
// UTILITY METHODS (Mock - replace with real implementations)
// ============================================================

func (as *AuthService) getMockUser(email string) *entities.User {
	// TODO: Replace with actual DB call
	// Demo user for testing
	hash, _ := crypto.HashPassword("TestPassword123!")
	return &entities.User{
		ID:               uuid.New().String(),
		Email:            email,
		PasswordHash:     hash,
		Role:             "doctor",
		FullName:         "Dr. Test User",
		TwoFactorEnabled: false,
		IsActive:         true,
		IsLocked:         false,
	}
}

func (as *AuthService) getMockUserByID(userID string) *entities.User {
	// TODO: Replace with actual DB call
	hash, _ := crypto.HashPassword("TestPassword123!")
	return &entities.User{
		ID:               userID,
		Email:            "doctor@medical.com",
		PasswordHash:     hash,
		Role:             "doctor",
		FullName:         "Dr. Test User",
		TwoFactorEnabled: true,
		TwoFactorSecret:  "JBSWY3DPEHPK3PXP",
		TwoFactorMethod:  entities.TwoFactorMethodTOTP,
		IsActive:         true,
		IsLocked:         false,
	}
}

func (as *AuthService) generateBackupCodes() []string {
	codes := make([]string, 10)
	for i := range codes {
		bytes := make([]byte, 4)
		rand.Read(bytes)
		codes[i] = fmt.Sprintf("%04X-%04X", binary.BigEndian.Uint16(bytes[:2]), binary.BigEndian.Uint16(bytes[2:4]))
	}
	return codes
}

func (as *AuthService) verifyBackupCode(user *entities.User, code string) bool {
	// TODO: Implementar verificación real de backup codes
	// Por ahora, aceptar cualquier código que empiezan con "BACKUP"
	return strings.HasPrefix(code, "BACKUP")
}

func (as *AuthService) verifyEmailCode(userID, code string) bool {
	// TODO: Implementar verificación de código enviado por email
	return false
}

func (as *AuthService) handleFailedLogin(user *entities.User, ip, userAgent string) {
	user.FailedLoginAttempts++
	user.LastFailedLogin = newTimePtr(time.Now())

	// Bloquear después de 5 intentos fallidos
	if user.FailedLoginAttempts >= 5 {
		user.IsLocked = true
		lockoutDuration := 15 * time.Minute
		lockoutUntil := time.Now().Add(lockoutDuration)
		user.LockoutUntil = &lockoutUntil
	}

	as.auditLogger.LogFailedAttempt(context.Background(), user.ID, ip, userAgent, "failed_login_attempt", "auth")
}

func (as *AuthService) updateSuccessfulLogin(user *entities.User, ip, userAgent string) {
	user.LastLogin = newTimePtr(time.Now())
	user.LastLoginIP = &ip
	user.LastLoginDevice = &userAgent
	user.FailedLoginAttempts = 0
	user.IsLocked = false
	user.LockoutUntil = nil
}

func newTimePtr(t time.Time) *time.Time {
	return &t
}

// Ensure interface implementation
var _ interface{} = (*AuthService)(nil)
