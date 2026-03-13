# Medical Records Manager - Backend API

## Comprehensive Technical Documentation

---

## What is This API?

The **Medical Records Manager** is a **secure REST API backend** for managing electronic medical records (EMR/EHR) in healthcare organizations.

### What It Does

| Functionality | Description |
|---------------|-------------|
| **Patient Data Management** | Secure storage and retrieval of patient PII (Personally Identifiable Information) |
| **Medical Records** | Create, read, update, and manage clinical records (consultations, diagnoses, prescriptions, lab results) |
| **User Authentication** | Secure login with Two-Factor Authentication (2FA) |
| **Access Control** | Role-based permissions (Doctor, Nurse, Admin, Receptionist, Patient) |
| **Audit Trail** | Complete logging of who did what, when, and from where |
| **Data Encryption** | All sensitive data encrypted at rest using AES-256-GCM |

### Compliance

This API is designed to comply with major healthcare data privacy regulations:

| Regulation | Region | Requirements Met |
|------------|--------|------------------|
| **HIPAA** | USA | Access control, audit controls, transmission security, encryption |
| **GDPR** | Europe | Data minimization, right to access/erasure, consent management |
| **LGPD** | Brazil | Data subject rights, consent, privacy by design |

### Use Cases

- Hospital information systems (HIS)
- Electronic Health Record (EHR) systems
- Clinic management software
- Telemedicine platforms
- Healthcare provider portals

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security Implementation](#security-implementation)
4. [Authentication System](#authentication-system)
5. [TOTP Two-Factor Authentication](#totp-two-factor-authentication)
6. [API Endpoints](#api-endpoints)
7. [Database Schema](#database-schema)
8. [Configuration](#configuration)
9. [Deployment](#deployment)
10. [Testing](#testing)
11. [Compliance](#compliance)
12. [Troubleshooting](#troubleshooting)

---

## Overview

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
├── cmd/api/main.go                 # Application entry point
├── internal/
│   ├── config/                     # Configuration management
│   ├── domain/                     # Business entities and interfaces
│   │   ├── entities/               # User, Patient, MedicalRecord, AuditLog
│   │   └── repositories/           # Repository interfaces
│   ├── infrastructure/
│   │   ├── auth/                   # Authentication service (2FA, JWT)
│   │   ├── crypto/                 # Encryption service (AES-256-GCM)
│   │   ├── database/               # PostgreSQL connection and repositories
│   │   └── logging/                # Audit logging system
│   └── transport/
│       ├── handlers/               # HTTP request handlers
│       ├── middleware/             # Security middleware
│       └── router/                 # Route configuration
├── pkg/constants/                  # Application constants
└── migrations/                     # Database schema
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

### Password Security

```go
// Password requirements
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character
- Maximum age: 90 days
```

### Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| X-Frame-Options | DENY | Prevent clickjacking |
| X-XSS-Protection | 1; mode=block | XSS filtering |
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| Content-Security-Policy | default-src 'self' | Prevent XSS/injection |
| Referrer-Policy | strict-origin-when-cross-origin | Privacy protection |

### Rate Limiting

- **Default**: 100 requests per minute per IP
- **Implementation**: In-memory sliding window algorithm

---

## Authentication System

### Two-Factor Authentication (2FA)

The system supports:

1. **TOTP (Time-based One-Time Password)** - RFC 6238 compliant
2. **Backup Codes** - 10 unique codes, single-use
3. **Email-based 2FA** (planned)

### Login Flow (2FA)

```
1. POST /auth/login
   → { email, password, device_info }
   
   If has 2FA:
   ← { require_two_factor: true, temp_token: "...", expires_in: 300 }
   
   If no 2FA:
   ← { access_token: "...", user: {...} }

2. POST /auth/verify-2fa
   → { temp_token: "...", code: "123456" }
   
   ← { access_token: "...", refresh_token: "...", user: {...} }
```

### Token Management

| Token Type | Expiry | Purpose |
|------------|--------|---------|
| **Access Token** | 15 minutes | API authentication |
| **Refresh Token** | 7 days | Token renewal |
| **Temp Token** | 5 minutes | 2FA verification |

### Account Lockout

- **Threshold**: 5 failed login attempts within 1 hour
- **Duration**: 15 minutes lockout
- **Tracking**: Stored in database for audit purposes

---

## TOTP Two-Factor Authentication

### What is TOTP?

**TOTP (Time-based One-Time Password)** is an algorithm that generates a temporary password that is valid for a short period (typically 30 seconds). It's the industry standard for 2FA, used by Google, Amazon, banks, and healthcare systems.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    HOW TOTP WORKS                               │
└─────────────────────────────────────────────────────────────────┘

   SERVER                    AUTH APP                    CLIENT
   ( SECRET )                                           
        │  1. User enables 2FA                                  
        │──────────────────►                                   
        │  2. Generate Secret Key (Base32)                      
        │◄───────────────────                                   
        │                      3. Scan QR with authenticator    
        │                      ───────────────────────────►      
        │                      4. App computes HOTP(T, secret)  
        │                      = 6-digit code (changes every 30s)
        │  5. User enters code                                   
        │◄───────────────────────►                               
        │  6. Verify: code == HMAC-SHA1(secret, T)              
```

### Algorithm Details

```
Formula: TOTP = HOTP(Secret, T)

Where:
  - T = floor(Unix_Time / 30)  ← Current 30-second window
  - Secret = Base32 encoded secret key (20 bytes)
  - HOTP = HMAC-SHA1(Secret, T) → Truncate to 6 digits
```

### Implementation

| Feature | Implementation |
|---------|----------------|
| **Algorithm** | RFC 6238 (TOTP) + RFC 4226 (HOTP) |
| **Time Window** | 30 seconds |
| **Tolerance** | ±1 window (90 seconds grace period) |
| **Digits** | 6 |
| **HMAC** | SHA-1 |
| **Secret Length** | 160 bits (20 bytes) |
| **Compatibility** | Google Authenticator, Authy, Microsoft Authenticator, 1Password |

### Setting Up TOTP

1. **Request 2FA setup**:
   ```bash
   POST /api/v1/auth/2fa/setup
   Authorization: Bearer <token>
   { "password": "current_password", "method": "totp" }
   ```

2. **Server returns**:
   ```json
   {
     "secret": "JBSWY3DPEHPK3PXP",
     "secret_base32": "JBSWY3DPEHPK3PXP",
     "qr_code_url": "otpauth://totp/MedicalRecords:user@hospital.com?secret=JBSWY3DPEHPK3PXP",
     "backup_codes": ["A1B2-C3D4", "E5F6-G7H8", ...]
   }
   ```

3. **Scan QR code** with authenticator app

4. **Verify with first code**:
   ```bash
   POST /api/v1/auth/2fa/verify
   X-2FA-Secret: <secret>
   { "code": "123456" }
   ```

### Backup Codes

When enabling 2FA, the user receives **10 backup codes**:
- Each code can only be used **once**
- Use when user loses access to authenticator app
- After all codes used, must regenerate new codes

---

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| POST | `/api/v1/auth/login` | Login (step 1) |
| POST | `/api/v1/auth/verify-2fa` | Verify 2FA (step 2) |
| GET | `/api/v1/auth/password-requirements` | Password rules |

### Protected Endpoints (Require JWT)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/2fa/setup` | Setup 2FA |
| POST | `/api/v1/auth/2fa/verify` | Verify 2FA setup |
| POST | `/api/v1/auth/2fa/disable` | Disable 2FA |
| POST | `/api/v1/auth/change-password` | Change password |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/medical-records` | Create record |
| GET | `/api/v1/medical-records/patient/:id` | Get patient records |
| GET | `/api/v1/medical-records/:id` | Get record |
| DELETE | `/api/v1/medical-records/:id` | Delete record |

### Example: Login with 2FA

```bash
# Step 1: Login with credentials
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "doctor@hospital.com", "password": "SecurePass123!"}'

# Response if 2FA enabled:
{
  "require_two_factor": true,
  "two_factor_method": "totp",
  "temp_token": "eyJ...",
  "expires_in": 300
}

# Step 2: Verify 2FA code
curl -X POST http://localhost:8080/api/v1/auth/verify-2fa \
  -H "Content-Type: application/json" \
  -d '{"temp_token": "eyJ...", "code": "123456"}'

# Response:
{
  "access_token": "eyJ...",
  "refresh_token": "...",
  "expires_in": 900,
  "user": { "id": "...", "email": "...", "role": "doctor" }
}
```

---

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email CITEXT UNIQUE,
    password_hash TEXT,
    role VARCHAR(50),  -- admin, doctor, nurse, receptionist, patient
    full_name TEXT,
    
    -- 2FA
    two_factor_enabled BOOLEAN DEFAULT false,
    two_factor_method VARCHAR(20),  -- totp, email, sms
    two_factor_secret TEXT,         -- Encrypted
    backup_codes_hash TEXT[],
    
    -- Security
    is_active BOOLEAN DEFAULT true,
    is_locked BOOLEAN DEFAULT false,
    failed_login_attempts INTEGER DEFAULT 0,
    lockout_until TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Patients Table (PII - Encrypted)

```sql
CREATE TABLE patients (
    id UUID PRIMARY KEY,
    pseudonym_id VARCHAR(100) UNIQUE,  -- Public ID (not linkable)
    
    -- Encrypted PII
    encrypted_full_name TEXT,
    encrypted_ssn TEXT,
    encrypted_address TEXT,
    encrypted_phone TEXT,
    encrypted_email TEXT,
    encrypted_emergency_contact TEXT,
    encrypted_insurance_number TEXT,
    
    -- Non-sensitive
    date_of_birth DATE,
    gender VARCHAR(20),
    blood_type VARCHAR(10),
    
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
    id UUID PRIMARY KEY,
    patient_id UUID REFERENCES patients(id),
    record_type VARCHAR(50),  -- consultation, diagnosis, prescription, etc.
    encrypted_content TEXT,   -- Encrypted clinical data
    provider_id UUID REFERENCES users(id),
    visit_date DATE,
    is_confidential BOOLEAN,
    is_active BOOLEAN DEFAULT true,
    deleted_at TIMESTAMPTZ,   -- Soft delete
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Audit Logs Table (Immutable)

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Never modified
    user_id UUID REFERENCES users(id),
    user_role VARCHAR(50),
    ip_address INET NOT NULL,
    user_agent TEXT,
    event_type VARCHAR(100),
    resource_type VARCHAR(100),
    resource_id UUID,
    action VARCHAR(50),
    details JSONB,
    success BOOLEAN DEFAULT true,
    error_message TEXT
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
| `JWT_SECRET` | JWT signing secret | - | **Yes** |
| `JWT_EXPIRATION` | JWT expiry | `15m` | No |
| `ENCRYPTION_KEY` | AES-256 key (64 hex chars) | - | **Yes** |
| `RATE_LIMIT` | Requests per minute | `100` | No |
| `ENVIRONMENT` | Environment | `development` | No |
| `AUDIT_RETENTION_DAYS` | Audit log retention | `2190` (6 years) | No |

### Example .env File

```bash
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
DB_HOST=localhost
DB_PORT=5432
DB_USER=medical_user
DB_PASSWORD=CHANGE_ME_IN_PRODUCTION
DB_NAME=medical_records
JWT_SECRET=super_secret_jwt_key_32_chars_minimum
ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
RATE_LIMIT=100
ENVIRONMENT=development
```

---

## Deployment

### Docker Deployment

```bash
# Start all services
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

---

## Testing

### Run Tests

```bash
# All tests
go test ./... -v

# With coverage
go test -cover ./...
```

### Test Results

```
=== RUN   TestTOTPService
    --- PASS: GenerateSecret generates valid base32 secret
    --- PASS: GenerateCode produces 6-digit code
    --- PASS: VerifyCode accepts current code
    --- PASS: VerifyCode rejects invalid code
    --- PASS: GetAuthenticatorURI generates correct format
--- PASS (5 tests)

=== RUN   TestAuthService/ValidatePassword
    --- PASS: Rejects weak passwords
    --- PASS: Accepts strong passwords
--- PASS (2 tests)

=== RUN   TestEncryption
    --- PASS: All 5 tests
--- PASS (5 tests)

=== RUN   TestPasswordHashing
    --- PASS: All 4 tests
--- PASS (4 tests)

TOTAL: 21 tests PASSED ✓
```

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

---

## Troubleshooting

### Common Issues

| Error | Solution |
|-------|----------|
| `connection refused` | Check PostgreSQL is running: `docker-compose up -d postgres` |
| `signature is invalid` | Verify `JWT_SECRET` matches across restarts |
| `invalid encryption key` | Ensure `ENCRYPTION_KEY` is exactly 64 hex characters |
| `invalid 2FA code` | Ensure device time is synchronized |

### Health Check

```bash
curl http://localhost:8080/health
# Response: { "status": "healthy", "service": "medical-records-manager" }
```

---

## License

**PROPRIETARY - ALL RIGHTS RESERVED**

See LICENSE file for full terms and conditions.

---

*Documentation Version: 1.0.0*  
*Last Updated: March 2026*  
*Project: Medical Records Manager*  
*Compliance: HIPAA | GDPR | LGPD*