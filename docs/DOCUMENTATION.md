# Medical Records Manager - Backend

## Comprehensive Technical Documentation

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security Implementation](#security-implementation)
4. [Authentication System](#authentication-system)
5. [API Endpoints](#api-endpoints)
6. [Database Schema](#database-schema)
7. [Configuration](#configuration)
8. [Deployment](#deployment)
9. [Testing](#testing)
10. [Compliance](#compliance)
11. [Troubleshooting](#troubleshooting)

---

## Overview

### Project Description

The **Medical Records Manager** is a robust, HIPAA-compliant backend system for managing electronic medical records (EMR). It provides secure storage, retrieval, and management of patient health information with strict adherence to data privacy regulations including HIPAA (USA), GDPR (Europe), and LGPD (Brazil).

### Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| **Language** | Go (Golang) | 1.21+ |
| **Framework** | Gin Web Framework | 1.9.x |
| **Database** | PostgreSQL | 15+ |
| **ORM** | pgx (pure Go driver) | 5.x |
| **Authentication** | JWT + TOTP 2FA | - |
| **Encryption** | AES-256-GCM | - |
| **Container** | Docker | - |

### Key Features

- **Two-Factor Authentication (2FA)**: TOTP-based and backup codes
- **Role-Based Access Control (RBAC)**: Granular permission system
- **End-to-End Encryption**: AES-256-GCM for sensitive data at rest
- **Audit Logging**: Immutable audit trail for all operations
- **Soft Deletes**: GDPR-compliant data retention with deletion workflows
- **Password Security**: Strong password requirements (12+ chars, complexity rules)
- **Rate Limiting**: API protection against abuse
- **Security Headers**: XSS, CSRF, and clickjacking protection

---

## Architecture

### Clean Architecture Design

The project follows **Clean Architecture** principles with clear separation of concerns:

```
medical-records-manager/
├── cmd/
│   └── api/
│       └── main.go                 # Application entry point
│
├── internal/
│   ├── config/
│   │   └── config.go               # Configuration management
│   │
│   ├── domain/
│   │   ├── entities/               # Business entities (User, Patient, MedicalRecord)
│   │   └── repositories/           # Repository interfaces
│   │
│   ├── infrastructure/
│   │   ├── auth/                   # Authentication service (2FA, JWT)
│   │   ├── crypto/                 # Encryption service (AES-256-GCM)
│   │   ├── database/               # PostgreSQL connection and repositories
│   │   └── logging/                # Audit logging system
│   │
│   └── transport/
│       ├── handlers/               # HTTP request handlers
│       ├── middleware/             # Security middleware (CORS, Rate Limit)
│       └── router/                 # Route configuration
│
├── pkg/
│   └── constants/                  # Application constants
│
└── migrations/
    └── 001_initial_schema.sql      # Database schema
```

### Layer Responsibilities

| Layer | Responsibility |
|-------|----------------|
| **Transport** | HTTP handling, request/response formatting, routing |
| **Application** | Business logic, use cases, orchestration |
| **Domain** | Business entities, repository interfaces, validation rules |
| **Infrastructure** | Database access, external services, encryption |

---

## Security Implementation

### Encryption at Rest

All sensitive patient information (PII) is encrypted using **AES-256-GCM** before storage:

```go
// internal/infrastructure/crypto/encryption.go
type Encryptor struct {
    aesGCM cipher.AEAD
}

// Encrypts data using AES-256-GCM
// Returns: nonce|ciphertext|tag (hex encoded)
func (e *Encryptor) Encrypt(plaintext string) (string, error)
```

**Encrypted Fields:**
- Patient full name
- Social Security Number (SSN)
- Address
- Phone number
- Email
- Emergency contact
- Insurance number
- Medical record content

### Encryption in Transit

- **TLS 1.2+** required for all production connections
- **HSTS** header configured for production deployments
- **Certificate Pinning** recommended for mobile clients

### Password Security

Passwords are hashed using **SHA-256 with salt** (production should use Argon2):

```go
// Password requirements
const (
    MinPasswordLength     = 12
    RequireUppercase      = true
    RequireLowercase      = true
    RequireNumbers        = true
    RequireSpecialChars   = true
    MaxPasswordAge        = 90 days
)
```

### Security Headers

The application implements the following security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| X-Frame-Options | DENY | Prevent clickjacking |
| X-XSS-Protection | 1; mode=block | XSS filtering |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| Content-Security-Policy | default-src 'self' | Prevent XSS/injection |
| Referrer-Policy | strict-origin-when-cross-origin | Privacy protection |
| Permissions-Policy | geolocation=(), microphone=(), camera=() | Restrict device access |

### Rate Limiting

- **Default**: 100 requests per minute per IP
- **Configurable** via `RATE_LIMIT` environment variable
- **Implementation**: In-memory sliding window algorithm

---

## Authentication System

### Two-Factor Authentication (2FA)

The system supports three 2FA methods:

1. **TOTP (Time-based One-Time Password)**
   - RFC 6238 compliant
   - Compatible with Google Authenticator, Authy, etc.
   - 30-second time window with 1-window tolerance

2. **Backup Codes**
   - 10 unique codes generated on 2FA setup
   - Single-use only
   - Displayed once, must be saved by user

3. **Email-based 2FA** (planned)
   - Code sent to registered email

### Login Flow (2FA)

```
┌──────────────────────────────────────────────────────────────────────┐
│                        LOGIN FLOW WITH 2FA                          │
└──────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐                         ┌──────────────┐
    │   CLIENT     │                         │    SERVER   │
    └──────────────┘                         └──────────────┘
          │                                        │
          │  1. POST /auth/login                  │
          │  { email, password, device_info }    │
          │ ──────────────────────────────────► │
          │                                        │
          │                                ┌──────┴──────┐
          │                                │ Validate    │
          │                                │ credentials │
          │                                └──────┬──────┘
          │                                        │
    ┌─────┴─────┐                           ┌──────┴──────┐
    │           │                           │             │
    │ INVALID   │                    ┌─────┴─────┐  ┌──┴────────┐
    │           │                    │           │  │           │
    ▼           │                    ▼           │  ▼           │
  ERROR  ◄──────┼────────────────◄───────────────┼───────────────┼──►
    │           │                    │           │  │           │
    │           │              ┌─────┴─────┐     │  │  ┌────────┴────────┐
    │           │              │ No 2FA    │     │  │  │ Has 2FA          │
    │           │              │ enabled   │     │  │  │ (Step 2)         │
    │           │              └─────┬─────┘     │  │  └────────┬────────┘
    │           │                    │           │  │           │
    │           │                    ▼           │  │           │
    │           │              ┌─────────────┐     │  │           │
    │           │              │ Return JWT  │     │  │           │
    │           │              │ directly    │     │  │           │
    │           │              └─────────────┘     │  │           │
    │           │                                    │  │           │
    │           │                          ┌────────┴──┐│  │  ┌────────┴────────┐
    │           │                          │ Return    ││  │  │ 2. POST /auth/  │
    │           │                          │ temp_token││  │  │ verify-2fa      │
    │           │                          └───────────┘│  │  │ { temp_token,   │
    │           │                                         │  │  │  code }         │
    │           │                                         │  │  ├────────────────►│
    │           │                                         │  │  │                 │
    │           │                                         │  │  │ Validate 2FA   │
    │           │                                         │  │  │ code or backup │
    │           │                                         │  │  │                │
    │           │                                         │  │  └───────┬────────┘
    │           │                                         │  │          │
    │           │                          ┌──────────────┴──┴──────────┐│
    │           │                          │ Return JWT + Refresh Token ││
    │           │                          └────────────────────────────┘│
    │           │                                        │              │
    ▼           ▼                                        ▼              ▼
```

### Token Management

| Token Type | Expiry | Purpose |
|------------|--------|---------|
| **Access Token** | 15 minutes (configurable) | API authentication |
| **Refresh Token** | 7 days (configurable) | Token renewal |
| **Temp Token** | 5 minutes | 2FA verification |

### Account Lockout

- **Threshold**: 5 failed login attempts within 1 hour
- **Duration**: 15 minutes lockout
- **Tracking**: Stored in database for audit purposes

---

## API Endpoints

### Public Endpoints

#### Health Check
```
GET /health
GET /ready
```
**Response:**
```json
{
  "status": "healthy",
  "service": "medical-records-manager"
}
```

#### Login (Step 1)
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "doctor@hospital.com",
  "password": "SecurePassword123!",
  "device_info": "Chrome on Windows 11"
}
```

**Response (requires 2FA):**
```json
{
  "require_two_factor": true,
  "two_factor_method": "totp",
  "temp_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6InRlbXAiLCJleHAi...",
  "expires_in": 300,
  "message": "Please verify your identity with 2FA"
}
```

**Response (no 2FA):**
```json
{
  "message": "Login successful",
  "data": {
    "user": {
      "id": "uuid",
      "email": "doctor@hospital.com",
      "role": "doctor",
      "full_name": "Dr. John Smith"
    }
  }
}
```

#### Password Requirements
```
GET /api/v1/auth/password-requirements
```

**Response:**
```json
{
  "min_length": 12,
  "require_upper": true,
  "require_lower": true,
  "require_number": true,
  "require_special": true,
  "max_age_days": 90
}
```

### Protected Endpoints (Require JWT)

All protected endpoints require the header:
```
Authorization: Bearer <access_token>
```

#### Verify 2FA (Step 2)
```
POST /api/v1/auth/verify-2fa
Content-Type: application/json

{
  "temp_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6InRlbXAiLCJleHAi...",
  "code": "123456"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6ImFjY2VzcyIsImV4cCI6...",
  "refresh_token": "a1b2c3d4e5f6...",
  "expires_in": 900,
  "password_expired": false,
  "user": {
    "id": "uuid",
    "email": "doctor@hospital.com",
    "role": "doctor",
    "full_name": "Dr. John Smith",
    "two_factor_enabled": true
  }
}
```

#### Setup 2FA
```
POST /api/v1/auth/2fa/setup
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "current_password",
  "method": "totp"
}
```

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/MedicalRecords:doctor@hospital.com?secret=JBSWY3DPEHPK3PXP&issuer=MedicalRecords",
  "backup_codes": [
    "A1B2-C3D4",
    "E5F6-G7H8",
    ...
  ],
  "message": "Save these backup codes in a secure place..."
}
```

#### Verify 2FA Setup
```
POST /api/v1/auth/2fa/verify
Authorization: Bearer <access_token>
X-2FA-Secret: <secret_from_setup>
Content-Type: application/json

{
  "code": "123456"
}
```

#### Disable 2FA
```
POST /api/v1/auth/2fa/disable
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "current_password",
  "code": "123456"
}
```

#### Change Password
```
POST /api/v1/auth/change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "current_password": "old_password",
  "new_password": "NewSecurePassword123!",
  "confirm_password": "NewSecurePassword123!"
}
```

#### Logout
```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "all_sessions": false
}
```

### Medical Records Endpoints

#### Create Medical Record
```
POST /api/v1/medical-records
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "patient_id": "uuid",
  "record_type": "consultation",
  "content": "Patient presents with...",
  "visit_date": "2024-01-15",
  "is_confidential": false
}
```

#### Get Medical Records by Patient
```
GET /api/v1/medical-records/patient/:patientID?limit=50&offset=0
Authorization: Bearer <access_token>
```

#### Get Medical Record by ID
```
GET /api/v1/medical-records/:id
Authorization: Bearer <access_token>
```

#### Delete Medical Record (Soft Delete)
```
DELETE /api/v1/medical-records/:id
Authorization: Bearer <access_token>
```

---

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email CITEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'doctor', 'nurse', 'receptionist', 'patient')),
    full_name TEXT NOT NULL,
    department TEXT,
    license_number TEXT,
    
    -- 2FA
    two_factor_enabled BOOLEAN DEFAULT false,
    two_factor_method VARCHAR(20),
    two_factor_secret TEXT,  -- Encrypted
    backup_codes_hash TEXT[],
    
    -- Security
    is_active BOOLEAN DEFAULT true,
    is_locked BOOLEAN DEFAULT false,
    failed_login_attempts INTEGER DEFAULT 0,
    lockout_until TIMESTAMPTZ,
    last_failed_login TIMESTAMPTZ,
    
    -- Password
    password_changed_at TIMESTAMPTZ,
    must_change_password BOOLEAN DEFAULT false,
    
    -- Session
    last_login TIMESTAMPTZ,
    last_login_ip INET,
    last_login_device TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Patients Table (PII - Encrypted)

```sql
CREATE TABLE patients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pseudonym_id VARCHAR(100) NOT NULL UNIQUE,
    
    -- Encrypted PII
    encrypted_full_name TEXT NOT NULL,
    encrypted_ssn TEXT NOT NULL,
    encrypted_address TEXT NOT NULL,
    encrypted_phone TEXT NOT NULL,
    encrypted_email TEXT NOT NULL,
    encrypted_emergency_contact TEXT,
    encrypted_insurance_number TEXT,
    
    -- Non-sensitive
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20) CHECK (gender IN ('male', 'female', 'other')),
    blood_type VARCHAR(10),
    insurance_provider TEXT,
    
    -- Soft delete
    is_active BOOLEAN DEFAULT true,
    deleted_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Medical Records Table

```sql
CREATE TABLE medical_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID REFERENCES patients(id),
    record_type VARCHAR(50) CHECK (...),
    encrypted_content TEXT NOT NULL,  -- Encrypted clinical data
    provider_id UUID REFERENCES users(id),
    facility_id VARCHAR(100),
    visit_date DATE NOT NULL,
    is_confidential BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    deleted_at TIMESTAMPTZ,  -- Soft delete
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Audit Logs Table (Immutable)

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Never modified
    user_id UUID REFERENCES users(id),
    user_role VARCHAR(50),
    ip_address INET NOT NULL,
    user_agent TEXT,
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    action VARCHAR(50) NOT NULL,
    details JSONB,
    success BOOLEAN DEFAULT true,
    error_message TEXT
);

-- Indexes for efficient querying
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
```

### Sessions Table

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT,
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_info TEXT,
    two_factor_verified BOOLEAN DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
```

### Login Attempts Table

```sql
CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    email CITEXT NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN DEFAULT false,
    failure_reason VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SERVER_HOST` | Server bind address | `0.0.0.0` | No |
| `SERVER_PORT` | Server port | `8080` | No |
| `DB_HOST` | PostgreSQL host | `localhost` | Yes |
| `DB_PORT` | PostgreSQL port | `5432` | No |
| `DB_USER` | PostgreSQL user | - | Yes |
| `DB_PASSWORD` | PostgreSQL password | - | Yes |
| `DB_NAME` | Database name | `medical_records` | No |
| `DB_SSL_MODE` | SSL mode | `require` | No |
| `JWT_SECRET` | JWT signing secret | - | **Yes** |
| `JWT_EXPIRATION` | JWT expiry | `15m` | No |
| `REFRESH_TOKEN_EXPIRY` | Refresh token expiry | `168h` (7 days) | No |
| `ENCRYPTION_KEY` | AES-256 key (64 hex chars) | - | **Yes** |
| `RATE_LIMIT` | Requests per minute | `100` | No |
| `ENVIRONMENT` | Environment | `development` | No |
| `AUDIT_RETENTION_DAYS` | Audit log retention | `2190` (6 years) | No |

### Example .env File

```bash
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=medical_user
DB_PASSWORD=CHANGE_ME_IN_PRODUCTION
DB_NAME=medical_records
DB_SSL_MODE=require

# Security (CHANGE IN PRODUCTION!)
JWT_SECRET=super_secret_jwt_key_32_chars_minimum
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Configuration
RATE_LIMIT=100
ENVIRONMENT=development
```

---

## Deployment

### Docker Deployment

```bash
# Start PostgreSQL and API
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f api

# Stop
docker-compose down
```

### Manual Deployment

```bash
# Build
go build -o server ./cmd/api

# Run
./server
```

### Production Considerations

1. **Change default secrets** - Never use default values in production
2. **Enable TLS** - Use reverse proxy (nginx, traefik) with SSL/TLS
3. **Database encryption** - Enable PostgreSQL encryption at rest
4. **Firewall** - Restrict access to database and API ports
5. **Monitoring** - Set up logging and alerting
6. **Backups** - Regular automated database backups

---

## Testing

### Unit Tests

The project includes unit tests for critical components:

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...
```

### API Testing

```bash
# Health check
curl http://localhost:8080/health

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "doctor@hospital.com", "password": "TestPassword123!"}'
```

### Security Testing Checklist

- [ ] Verify encryption of PII at rest
- [ ] Test account lockout after failed attempts
- [ ] Verify audit logging of all operations
- [ ] Test 2FA flow end-to-end
- [ ] Verify role-based access control
- [ ] Test rate limiting behavior
- [ ] Verify security headers
- [ ] Test password requirements enforcement

---

## Compliance

### HIPAA Compliance

| Requirement | Implementation |
|-------------|----------------|
| **Access Control** | RBAC with role-based permissions |
| **Audit Controls** | Immutable audit_logs table |
| **Integrity Controls** | Soft deletes, cryptographic hashing |
| **Transmission Security** | TLS support, encryption at rest |
| **Person or Entity Authentication** | JWT + 2FA authentication |
| **Password Requirements** | 12+ chars, complexity rules, expiry |

### GDPR Compliance

| Requirement | Implementation |
|-------------|----------------|
| **Data Minimization** | PII separated from clinical data |
| **Right to Access** | data_access_requests table |
| **Right to Erasure** | Soft delete with retention policy |
| **Consent Management** | consents table |
| **Data Portability** | Export functionality |
| **Data Protection** | Encryption, pseudonymization |

### LGPD Compliance

The system follows GDPR principles which satisfy LGPD requirements:
- Lawful basis for processing
- Consent management
- Data subject rights
- Data protection by design

---

## Troubleshooting

### Common Issues

#### Database Connection Failed
```
Error: dial tcp localhost:5432: connect: connection refused
```
**Solution:** Ensure PostgreSQL is running (`docker-compose up -d postgres`)

#### Invalid JWT Token
```
Error: signature is invalid
```
**Solution:** Verify `JWT_SECRET` environment variable matches across restarts

#### Encryption Key Error
```
Error: invalid encryption key: must be 32 bytes
```
**Solution:** Ensure `ENCRYPTION_KEY` is exactly 64 hex characters

#### 2FA Code Invalid
```
Error: invalid 2FA code
```
**Solution:** Ensure device time is synchronized (TOTP is time-based)

### Log Locations

| Environment | Log Location |
|-------------|--------------|
| Docker | `docker-compose logs api` |
| Local | stdout/stderr |

### Health Check

```bash
# Basic health
curl http://localhost:8080/health

# Readiness
curl http://localhost:8080/ready

# Database connection
docker-compose exec postgres pg_isready -U medical_user -d medical_records
```

---

## API Reference Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/ready` | No | Readiness check |
| POST | `/api/v1/auth/login` | No | Login (step 1) |
| POST | `/api/v1/auth/verify-2fa` | No | Verify 2FA (step 2) |
| GET | `/api/v1/auth/password-requirements` | No | Password rules |
| POST | `/api/v1/auth/2fa/setup` | JWT | Setup 2FA |
| POST | `/api/v1/auth/2fa/verify` | JWT | Verify 2FA setup |
| POST | `/api/v1/auth/2fa/disable` | JWT | Disable 2FA |
| POST | `/api/v1/auth/change-password` | JWT | Change password |
| POST | `/api/v1/auth/logout` | JWT | Logout |
| POST | `/api/v1/medical-records` | JWT | Create record |
| GET | `/api/v1/medical-records/patient/:id` | JWT | Get patient records |
| GET | `/api/v1/medical-records/:id` | JWT | Get record |
| DELETE | `/api/v1/medical-records/:id` | JWT | Delete record |

---

## Support and Contributing

### Reporting Issues

For bugs or feature requests, please create an issue in the project repository.

### Security Vulnerabilities

If you discover a security vulnerability, please contact the security team immediately.

---

*Documentation Version: 1.0.0*  
*Last Updated: March 2026*  
*Project: Medical Records Manager*  
*Compliance: HIPAA | GDPR | LGPD*