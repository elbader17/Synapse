package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"medical-records-manager/internal/domain/entities"
)

// UserRepository maneja la persistencia de usuarios
type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*entities.User, error)
	GetByID(ctx context.Context, id string) (*entities.User, error)
	Create(ctx context.Context, user *entities.User) error
	Update(ctx context.Context, user *entities.User) error
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	Enable2FA(ctx context.Context, userID, method, secret string, backupCodes []string) error
	Disable2FA(ctx context.Context, userID string) error
	RecordLoginAttempt(ctx context.Context, email, ip, userAgent string, success bool, reason string) error
	LockUser(ctx context.Context, userID string, duration time.Duration) error
	UnlockUser(ctx context.Context, userID string) error
}

// PostgresUserRepository implementa UserRepository para PostgreSQL
type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresUserRepository crea una nueva instancia del repositorio
func NewPostgresUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

// GetByEmail obtiene un usuario por email
func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	query := `
		SELECT id, email, password_hash, role, full_name, department, license_number,
		       two_factor_enabled, two_factor_method, two_factor_secret, backup_codes,
		       is_active, is_locked, failed_login_attempts, lockout_until, last_failed_login,
		       password_changed_at, must_change_password, last_login, last_login_ip, 
		       last_login_device, created_at, updated_at
		FROM users
		WHERE email = $1 AND is_active = true
	`

	var user entities.User
	var twoFactorMethod, twoFactorSecret, lastLoginIP, lastLoginDevice pgtype

	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.FullName,
		&user.Department,
		&user.License,
		&user.TwoFactorEnabled,
		&twoFactorMethod,
		&twoFactorSecret,
		&user.BackupCodes,
		&user.IsActive,
		&user.IsLocked,
		&user.FailedLoginAttempts,
		&user.LockoutUntil,
		&user.LastFailedLogin,
		&user.PasswordChangedAt,
		&user.MustChangePassword,
		&user.LastLogin,
		&lastLoginIP,
		&lastLoginDevice,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Convertir tipos
	if lastLoginIP.Valid {
		user.LastLoginIP = newStringPtr(lastLoginIP.String)
	}
	if lastLoginDevice.Valid {
		user.LastLoginDevice = newStringPtr(lastLoginDevice.String)
	}
	if twoFactorSecret.Valid {
		user.TwoFactorSecret = twoFactorSecret.String
	}
	if twoFactorMethod.Valid {
		user.TwoFactorMethod = twoFactorMethod.String
	}

	return &user, nil
}

// GetByID obtiene un usuario por ID
func (r *PostgresUserRepository) GetByID(ctx context.Context, id string) (*entities.User, error) {
	query := `
		SELECT id, email, password_hash, role, full_name, department, license_number,
		       two_factor_enabled, two_factor_method, two_factor_secret, backup_codes,
		       is_active, is_locked, failed_login_attempts, lockout_until, last_failed_login,
		       password_changed_at, must_change_password, last_login, last_login_ip, 
		       last_login_device, created_at, updated_at
		FROM users
		WHERE id = $1 AND is_active = true
	`

	var user entities.User
	var twoFactorMethod, twoFactorSecret, lastLoginIP, lastLoginDevice pgtype

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.FullName,
		&user.Department,
		&user.License,
		&user.TwoFactorEnabled,
		&twoFactorMethod,
		&twoFactorSecret,
		&user.BackupCodes,
		&user.IsActive,
		&user.IsLocked,
		&user.FailedLoginAttempts,
		&user.LockoutUntil,
		&user.LastFailedLogin,
		&user.PasswordChangedAt,
		&user.MustChangePassword,
		&user.LastLogin,
		&lastLoginIP,
		&lastLoginDevice,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	if lastLoginIP.Valid {
		user.LastLoginIP = newStringPtr(lastLoginIP.String)
	}
	if lastLoginDevice.Valid {
		user.LastLoginDevice = newStringPtr(lastLoginDevice.String)
	}
	if twoFactorSecret.Valid {
		user.TwoFactorSecret = twoFactorSecret.String
	}
	if twoFactorMethod.Valid {
		user.TwoFactorMethod = twoFactorMethod.String
	}

	return &user, nil
}

// Create crea un nuevo usuario
func (r *PostgresUserRepository) Create(ctx context.Context, user *entities.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.CreatedAt = time.Now().UTC()
	user.UpdatedAt = time.Now().UTC()

	query := `
		INSERT INTO users (
			id, email, password_hash, role, full_name, department, license_number,
			is_active, is_locked, failed_login_attempts, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
	`

	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.FullName,
		user.Department,
		user.License,
		user.IsActive,
		user.IsLocked,
		user.FailedLoginAttempts,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// Update actualiza un usuario
func (r *PostgresUserRepository) Update(ctx context.Context, user *entities.User) error {
	user.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE users
		SET full_name = $2,
		    department = $3,
		    license_number = $4,
		    two_factor_enabled = $5,
		    two_factor_method = $6,
		    two_factor_secret = $7,
		    backup_codes = $8,
		    is_active = $9,
		    is_locked = $10,
		    failed_login_attempts = $11,
		    lockout_until = $12,
		    last_failed_login = $13,
		    password_changed_at = $14,
		    must_change_password = $15,
		    last_login = $16,
		    last_login_ip = $17,
		    last_login_device = $18,
		    updated_at = $19
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.FullName,
		user.Department,
		user.License,
		user.TwoFactorEnabled,
		user.TwoFactorMethod,
		user.TwoFactorSecret,
		user.BackupCodes,
		user.IsActive,
		user.IsLocked,
		user.FailedLoginAttempts,
		user.LockoutUntil,
		user.LastFailedLogin,
		user.PasswordChangedAt,
		user.MustChangePassword,
		user.LastLogin,
		user.LastLoginIP,
		user.LastLoginDevice,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UpdatePassword actualiza la contraseña de un usuario
func (r *PostgresUserRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	query := `
		UPDATE users
		SET password_hash = $2,
		    password_changed_at = $3,
		    must_change_password = false,
		    updated_at = $3
		WHERE id = $1
	`

	result, err := r.pool.Exec(ctx, query, userID, passwordHash, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// Enable2FA habilita 2FA para un usuario
func (r *PostgresUserRepository) Enable2FA(ctx context.Context, userID, method, secret string, backupCodes []string) error {
	query := `
		UPDATE users
		SET two_factor_enabled = true,
		    two_factor_method = $2,
		    two_factor_secret = $3,
		    backup_codes = $4,
		    updated_at = $5
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, userID, method, secret, backupCodes, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return nil
}

// Disable2FA deshabilita 2FA para un usuario
func (r *PostgresUserRepository) Disable2FA(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET two_factor_enabled = false,
		    two_factor_method = '',
		    two_factor_secret = NULL,
		    backup_codes = NULL,
		    updated_at = $2
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, userID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return nil
}

// RecordLoginAttempt registra un intento de login
func (r *PostgresUserRepository) RecordLoginAttempt(ctx context.Context, email, ip, userAgent string, success bool, reason string) error {
	// Primero obtener el user_id si existe
	var userID *string
	user, _ := r.GetByEmail(ctx, email)
	if user != nil {
		userID = &user.ID
	}

	query := `
		INSERT INTO login_attempts (id, user_id, email, ip_address, user_agent, success, failure_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.pool.Exec(ctx, query, uuid.New(), userID, email, ip, userAgent, success, reason)
	if err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	// Si fallido, actualizar contador del usuario
	if !success && user != nil {
		failedCount := user.FailedLoginAttempts + 1
		var lockout *time.Time

		if failedCount >= 5 {
			lockoutTime := time.Now().Add(15 * time.Minute)
			lockout = &lockoutTime
		}

		updateQuery := `
			UPDATE users
			SET failed_login_attempts = $2,
			    lockout_until = $3,
			    is_locked = $4,
			    last_failed_login = $5
			WHERE id = $1
		`

		_, err := r.pool.Exec(ctx, updateQuery, user.ID, failedCount, lockout, failedCount >= 5, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("failed to update failed login count: %w", err)
		}
	}

	return nil
}

// LockUser bloquea un usuario
func (r *PostgresUserRepository) LockUser(ctx context.Context, userID string, duration time.Duration) error {
	query := `
		UPDATE users
		SET is_locked = true,
		    lockout_until = $2,
		    updated_at = $2
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, userID, time.Now().Add(duration))
	if err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}

	return nil
}

// UnlockUser desbloquea un usuario
func (r *PostgresUserRepository) UnlockUser(ctx context.Context, userID string) error {
	query := `
		UPDATE users
		SET is_locked = false,
		    lockout_until = NULL,
		    failed_login_attempts = 0,
		    updated_at = $2
		WHERE id = $1
	`

	_, err := r.pool.Exec(ctx, query, userID, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	return nil
}

// Helper functions
func newStringPtr(s string) *string {
	return &s
}

// pgtype es necesario para manejar tipos nullable
// En implementación real, usar github.com/jackc/pgtype

type pgtype struct {
	Valid  bool
	String string
	Int    int
}

// Ensure interface implementation
var _ UserRepository = (*PostgresUserRepository)(nil)
