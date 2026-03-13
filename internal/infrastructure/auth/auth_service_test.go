package auth

import (
	"testing"

	"medical-records-manager/internal/config"
	"medical-records-manager/internal/infrastructure/crypto"
	"medical-records-manager/internal/infrastructure/logging"
)

// TestTOTPService tests the TOTP implementation
func TestTOTPService(t *testing.T) {
	totpService := NewTOTPService("TestApp")

	t.Run("GenerateSecret generates valid base32 secret", func(t *testing.T) {
		secret, err := totpService.GenerateSecret()
		if err != nil {
			t.Fatalf("GenerateSecret failed: %v", err)
		}
		if len(secret) == 0 {
			t.Error("Secret should not be empty")
		}
		// Base32 encoded secrets should only contain A-Z and 2-7
		for _, c := range secret {
			if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
				t.Errorf("Invalid base32 character: %c", c)
			}
		}
	})

	t.Run("GenerateCode produces 6-digit code", func(t *testing.T) {
		secret, _ := totpService.GenerateSecret()
		code := totpService.GenerateCode(secret)
		if len(code) != 6 {
			t.Errorf("Expected 6-digit code, got %d digits", len(code))
		}
	})

	t.Run("VerifyCode accepts current code", func(t *testing.T) {
		secret, _ := totpService.GenerateSecret()
		code := totpService.GenerateCode(secret)
		if !totpService.VerifyCode(secret, code) {
			t.Error("Should accept current code")
		}
	})

	t.Run("VerifyCode rejects invalid code", func(t *testing.T) {
		secret, _ := totpService.GenerateSecret()
		if totpService.VerifyCode(secret, "000000") {
			t.Error("Should reject invalid code")
		}
	})

	t.Run("GetAuthenticatorURI generates correct format", func(t *testing.T) {
		secret := "JBSWY3DPEHPK3PXP"
		uri := totpService.GetAuthenticatorURI(secret, "test@example.com")
		if len(uri) == 0 {
			t.Error("URI should not be empty")
		}
		if len(uri) < 50 {
			t.Errorf("URI seems too short: %s", uri)
		}
	})
}

// TestAuthService tests the authentication service
func TestAuthService(t *testing.T) {
	// Create test configuration
	cfg := &config.Config{
		JWTSecret:     "test_secret_key_32_characters_min",
		JWTExpiration: 15,
		EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	encryptor, _ := crypto.NewEncryptor(cfg.EncryptionKey)
	auditLogger := logging.NewAuditLogger(100, 1)
	defer auditLogger.Shutdown()

	authService := NewAuthService(cfg, encryptor, auditLogger)

	t.Run("ValidatePassword rejects weak passwords", func(t *testing.T) {
		tests := []struct {
			password string
			wantErr  bool
		}{
			{"short", true},            // Too short
			{"alllowercase", true},     // No uppercase
			{"ALLUPPERCASE", true},     // No lowercase
			{"NoSpecialChar1", true},   // No special char
			{"Valid1Password!", false}, // Valid
		}

		for _, tt := range tests {
			err := authService.ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		}
	})

	t.Run("ValidatePassword accepts strong passwords", func(t *testing.T) {
		validPasswords := []string{
			"StrongP@ssw0rd!",
			"CorrectHorseBatteryStaple123!",
			"Secure#Pass2024",
		}

		for _, pwd := range validPasswords {
			if err := authService.ValidatePassword(pwd); err != nil {
				t.Errorf("ValidatePassword(%q) failed: %v", pwd, err)
			}
		}
	})
}

// TestEncryption tests the encryption service
func TestEncryption(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	encryptor, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	t.Run("Encrypt produces non-empty output", func(t *testing.T) {
		ciphertext, err := encryptor.Encrypt("test data")
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Error("Ciphertext should not be empty")
		}
	})

	t.Run("Decrypt returns original data", func(t *testing.T) {
		original := "sensitive medical data"
		ciphertext, _ := encryptor.Encrypt(original)
		decrypted, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if decrypted != original {
			t.Errorf("Expected %q, got %q", original, decrypted)
		}
	})

	t.Run("Encrypt handles empty string", func(t *testing.T) {
		ciphertext, err := encryptor.Encrypt("")
		if err != nil {
			t.Errorf("Encrypt empty string should not fail: %v", err)
		}
		if ciphertext != "" {
			t.Error("Empty string should produce empty ciphertext")
		}
	})

	t.Run("Decrypt handles empty string", func(t *testing.T) {
		plaintext, err := encryptor.Decrypt("")
		if err != nil {
			t.Errorf("Decrypt empty string should not fail: %v", err)
		}
		if plaintext != "" {
			t.Error("Empty ciphertext should produce empty plaintext")
		}
	})

	t.Run("Encrypt produces different ciphertexts for same input", func(t *testing.T) {
		input := "test"
		ct1, _ := encryptor.Encrypt(input)
		ct2, _ := encryptor.Encrypt(input)
		// Due to random nonce, should be different
		if ct1 == ct2 {
			t.Error("Encryption should use random nonce")
		}
	})
}

// TestPasswordHashing tests password hashing
func TestPasswordHashing(t *testing.T) {
	t.Run("HashPassword produces valid hash", func(t *testing.T) {
		hash, err := crypto.HashPassword("testpassword")
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}
		if len(hash) == 0 {
			t.Error("Hash should not be empty")
		}
	})

	t.Run("VerifyPassword accepts correct password", func(t *testing.T) {
		password := "testpassword123!"
		hash, _ := crypto.HashPassword(password)
		if !crypto.VerifyPassword(password, hash) {
			t.Error("Should accept correct password")
		}
	})

	t.Run("VerifyPassword rejects incorrect password", func(t *testing.T) {
		password := "testpassword123!"
		hash, _ := crypto.HashPassword(password)
		if crypto.VerifyPassword("wrongpassword", hash) {
			t.Error("Should reject incorrect password")
		}
	})

	t.Run("VerifyPassword handles invalid hash format", func(t *testing.T) {
		if crypto.VerifyPassword("password", "invalid_hash") {
			t.Error("Should reject invalid hash format")
		}
	})
}

// TestTokenHashing tests token hashing
func TestTokenHashing(t *testing.T) {
	t.Run("HashToken produces consistent hashes", func(t *testing.T) {
		token := "test_token_12345"
		hash1 := crypto.HashToken(token)
		hash2 := crypto.HashToken(token)
		if hash1 != hash2 {
			t.Error("Same token should produce same hash")
		}
	})

	t.Run("HashToken produces different hashes for different tokens", func(t *testing.T) {
		hash1 := crypto.HashToken("token1")
		hash2 := crypto.HashToken("token2")
		if hash1 == hash2 {
			t.Error("Different tokens should produce different hashes")
		}
	})
}

// TestSecureCompare tests timing-safe comparison
func TestSecureCompare(t *testing.T) {
	t.Run("SecureCompare accepts equal strings", func(t *testing.T) {
		if !crypto.SecureCompare("test", "test") {
			t.Error("Should accept equal strings")
		}
	})

	t.Run("SecureCompare rejects different strings", func(t *testing.T) {
		if crypto.SecureCompare("test", "TEST") {
			t.Error("Should reject different strings")
		}
	})

	t.Run("SecureCompare rejects strings of different lengths", func(t *testing.T) {
		if crypto.SecureCompare("test", "testing") {
			t.Error("Should reject different length strings")
		}
	})
}

// TestGenerateRandomString tests random string generation
func TestGenerateRandomString(t *testing.T) {
	t.Run("GenerateRandomString produces correct length", func(t *testing.T) {
		for _, length := range []int{16, 32, 64} {
			s, err := crypto.GenerateRandomString(length)
			if err != nil {
				t.Errorf("GenerateRandomString(%d) failed: %v", length, err)
			}
			if len(s) != length {
				t.Errorf("Expected length %d, got %d", length, len(s))
			}
		}
	})

	t.Run("GenerateRandomString produces unique strings", func(t *testing.T) {
		s1, _ := crypto.GenerateRandomString(32)
		s2, _ := crypto.GenerateRandomString(32)
		if s1 == s2 {
			t.Error("Generated strings should be unique")
		}
	})
}

// Benchmark tests for performance evaluation
func BenchmarkTOTPGeneration(b *testing.B) {
	totpService := NewTOTPService("Benchmark")
	secret, _ := totpService.GenerateSecret()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		totpService.GenerateCode(secret)
	}
}

func BenchmarkEncryption(b *testing.B) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	encryptor, _ := crypto.NewEncryptor(key)
	data := "sensitive medical record data"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptor.Encrypt(data)
	}
}

func BenchmarkPasswordHashing(b *testing.B) {
	password := "SecureP@ssword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.HashPassword(password)
	}
}
