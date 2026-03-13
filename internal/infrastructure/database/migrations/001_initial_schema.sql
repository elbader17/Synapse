-- ============================================================
-- Medical Records Manager - DDL PostgreSQL (Enhanced with 2FA)
-- Cumplimiento: HIPAA, GDPR, LGPD
-- ============================================================

-- ============================================================
-- EXTENSIONES NECESARIAS
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";


-- ============================================================
-- 1. TABLA DE USUARIOS (Enhanced with 2FA)
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    -- Identificador único
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Credentials
    email CITEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    
    -- RBAC
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse', 'receptionist', 'patient')),
    full_name TEXT NOT NULL,
    department TEXT,
    license_number TEXT,
    
    -- 2FA Configuration
    two_factor_enabled BOOLEAN NOT NULL DEFAULT false,
    two_factor_method VARCHAR(20) CHECK (two_factor_method IN ('totp', 'email', 'sms', '')),
    two_factor_secret TEXT, -- Cifrado
    backup_codes_hash TEXT[], -- Hash de códigos de respaldo
    
    -- Security
    is_active BOOLEAN NOT NULL DEFAULT true,
    is_locked BOOLEAN NOT NULL DEFAULT false,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_until TIMESTAMPTZ,
    last_failed_login TIMESTAMPTZ,
    
    -- Password security
    password_changed_at TIMESTAMPTZ,
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    
    -- Session tracking
    last_login TIMESTAMPTZ,
    last_login_ip INET,
    last_login_device TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_is_locked ON users(is_locked);
CREATE INDEX idx_users_lockout_until ON users(lockout_until) WHERE lockout_until IS NOT NULL;


-- ============================================================
-- 2. TABLA DE PACIENTES (PII)
-- ============================================================

CREATE TABLE IF NOT EXISTS patients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pseudonym_id VARCHAR(100) NOT NULL UNIQUE,
    
    -- PII cifrados
    encrypted_full_name TEXT NOT NULL,
    encrypted_ssn TEXT NOT NULL,
    encrypted_address TEXT NOT NULL,
    encrypted_phone TEXT NOT NULL,
    encrypted_email TEXT NOT NULL,
    encrypted_emergency_contact TEXT,
    encrypted_insurance_number TEXT,
    
    -- Datos demográficos no sensibles
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20) NOT NULL CHECK (gender IN ('male', 'female', 'other')),
    blood_type VARCHAR(10),
    insurance_provider TEXT,
    
    -- Soft delete
    is_active BOOLEAN NOT NULL DEFAULT true,
    deleted_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_patients_updated_at
    BEFORE UPDATE ON patients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_patients_pseudonym ON patients(pseudonym_id);
CREATE INDEX idx_patients_is_active ON patients(is_active);


-- ============================================================
-- 3. TABLA DE REGISTROS MÉDICOS
-- ============================================================

CREATE TABLE IF NOT EXISTS medical_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES patients(id),
    record_type VARCHAR(50) NOT NULL CHECK (
        record_type IN ('consultation', 'diagnosis', 'prescription', 'lab_result', 'procedure', 'imaging', 'note')
    ),
    encrypted_content TEXT NOT NULL,
    provider_id UUID NOT NULL REFERENCES users(id),
    facility_id VARCHAR(100),
    visit_date DATE NOT NULL,
    is_confidential BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_medical_records_updated_at
    BEFORE UPDATE ON medical_records
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_medical_records_patient ON medical_records(patient_id);
CREATE INDEX idx_medical_records_provider ON medical_records(provider_id);
CREATE INDEX idx_medical_records_visit_date ON medical_records(visit_date);


-- ============================================================
-- 4. TABLA DE AUDITORÍA (CRÍTICA)
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID REFERENCES users(id),
    user_role VARCHAR(50),
    ip_address INET NOT NULL,
    user_agent TEXT,
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    action VARCHAR(50) NOT NULL CHECK (action IN ('create', 'read', 'update', 'delete', 'login', 'logout', 'failed_attempt', 'export')),
    details JSONB,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT
);

CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_success ON audit_logs(success);


-- ============================================================
-- 5. TABLA DE SESIONES (Login Sessions)
-- ============================================================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT,
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_info TEXT,
    two_factor_verified BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity);


-- ============================================================
-- 6. TABLA DE TOKENS TEMPORALES (para 2FA)
-- ============================================================

CREATE TABLE IF NOT EXISTS temp_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    token_type VARCHAR(20) NOT NULL CHECK (token_type IN ('2fa_setup', 'password_reset', 'email_verification')),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX idx_temp_tokens_user ON temp_tokens(user_id);
CREATE INDEX idx_temp_tokens_token_hash ON temp_tokens(token_hash);
CREATE INDEX idx_temp_tokens_expires ON temp_tokens(expires_at) WHERE used_at IS NULL;


-- ============================================================
-- 7. TABLA DE LOGIN ATTEMPTS (Tracking de intentos)
-- ============================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    email CITEXT NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT false,
    failure_reason VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_attempts_email ON login_attempts(email);
CREATE INDEX idx_login_attempts_created_at ON login_attempts(created_at);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address);

-- Función para limpiar intentos de login antiguos (más de 30 días)
CREATE OR REPLACE FUNCTION cleanup_old_login_attempts()
RETURNS void AS $$
BEGIN
    DELETE FROM login_attempts 
    WHERE created_at < NOW() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;


-- ============================================================
-- 8. TABLA DE CONSENTIMIENTO (GDPR/LGPD)
-- ============================================================

CREATE TABLE IF NOT EXISTS consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES patients(id),
    consent_type VARCHAR(50) NOT NULL CHECK (
        consent_type IN ('data_processing', 'data_sharing', 'marketing', 'research', 'access_log')
    ),
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    purpose TEXT,
    version VARCHAR(20),
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_consents_updated_at
    BEFORE UPDATE ON consents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_consents_patient ON consents(patient_id);


-- ============================================================
-- 9. TABLA DE SOLICITUDES DE ACCESO (GDPR Right to Access)
-- ============================================================

CREATE TABLE IF NOT EXISTS data_access_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES patients(id),
    requester_id UUID REFERENCES users(id),
    request_type VARCHAR(50) NOT NULL CHECK (
        request_type IN ('access', 'rectification', 'erasure', 'portability', 'restriction')
    ),
    status VARCHAR(50) NOT NULL CHECK (
        status IN ('pending', 'in_progress', 'completed', 'rejected')
    ),
    reason TEXT,
    response_data JSONB,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_data_access_requests_updated_at
    BEFORE UPDATE ON data_access_requests
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_data_access_requests_patient ON data_access_requests(patient_id);
CREATE INDEX idx_data_access_requests_status ON data_access_requests(status);


-- ============================================================
-- FUNCIONES UTILITARIAS
-- ============================================================

-- Función para Soft Delete
CREATE OR REPLACE FUNCTION soft_delete_patient(p_id UUID)
RETURNS VOID AS $$
BEGIN
    UPDATE patients 
    SET is_active = false, deleted_at = NOW()
    WHERE id = p_id;
    
    UPDATE medical_records
    SET is_active = false, deleted_at = NOW()
    WHERE patient_id = p_id;
END;
$$ LANGUAGE plpgsql;

-- Función para verificar consentimiento
CREATE OR REPLACE FUNCTION has_valid_consent(p_id UUID, c_type VARCHAR)
RETURNS BOOLEAN AS $$
DECLARE
    valid BOOLEAN;
BEGIN
    SELECT granted INTO valid
    FROM consents
    WHERE patient_id = p_id 
      AND consent_type = c_type
      AND granted = true
      AND revoked_at IS NULL
    ORDER BY created_at DESC
    LIMIT 1;
    
    RETURN COALESCE(valid, false);
END;
$$ LANGUAGE plpgsql;

-- Función para bloquear usuario tras intentos fallidos
CREATE OR REPLACE FUNCTION check_and_lock_user(user_email CITEXT)
RETURNS VOID AS $$
DECLARE
    failed_count INTEGER;
    user_id UUID;
BEGIN
    -- Contar intentos fallidos en la última hora
    SELECT COUNT(*), MAX(user_id) INTO failed_count, user_id
    FROM login_attempts
    WHERE email = user_email 
      AND success = false
      AND created_at > NOW() - INTERVAL '1 hour';
    
    IF failed_count >= 5 THEN
        UPDATE users 
        SET is_locked = true, 
            lockout_until = NOW() + INTERVAL '15 minutes'
        WHERE email = user_email;
    END IF;
END;
$$ LANGUAGE plpgsql;


-- ============================================================
-- VISTAS
-- ============================================================

-- Vista de sesiones activas
CREATE OR REPLACE VIEW v_active_sessions AS
SELECT 
    s.id,
    s.user_id,
    u.email,
    u.full_name,
    s.ip_address,
    s.device_info,
    s.two_factor_verified,
    s.expires_at,
    s.last_activity
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.revoked_at IS NULL AND s.expires_at > NOW();

-- Vista de usuarios bloqueados
CREATE OR REPLACE VIEW v_locked_users AS
SELECT 
    id, email, full_name, role, lockout_until, failed_login_attempts
FROM users
WHERE is_locked = true AND lockout_until > NOW();