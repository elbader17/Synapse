package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// Encryptor maneja el cifrado AES-256-GCM para datos sensibles
type Encryptor struct {
	aesGCM cipher.AEAD
}

// NewEncryptor crea un nuevo encryptor con la clave dada
// La clave debe ser 32 bytes (256 bits) para AES-256
func NewEncryptor(keyHex string) (*Encryptor, error) {
	// Convertir hex a bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, errors.New("invalid encryption key: must be valid hex")
	}

	// Verificar longitud (32 bytes = 256 bits)
	if len(key) != 32 {
		return nil, errors.New("invalid encryption key: must be 32 bytes (64 hex characters)")
	}

	// Crear bloque AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create AES cipher: " + err.Error())
	}

	// Crear modo GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to create GCM mode: " + err.Error())
	}

	return &Encryptor{aesGCM: aesGCM}, nil
}

// Encrypt cifra datos sensibles usando AES-256-GCM
// Devuelve el texto cifrado en formato: nonce|ciphertext|tag
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// Crear nonce aleatorio
	nonce := make([]byte, e.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New("failed to generate nonce: " + err.Error())
	}

	// Cifrar
	ciphertext := e.aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Devolver como string base64 o hex
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt descifra datos usando AES-256-GCM
func (e *Encryptor) Decrypt(ciphertextHex string) (string, error) {
	if ciphertextHex == "" {
		return "", nil
	}

	// Decodificar hex
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", errors.New("invalid ciphertext format")
	}

	// Verificar tamaño mínimo
	nonceSize := e.aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	// Extraer nonce y ciphertext
	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Descifrar
	plaintext, err := e.aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", errors.New("decryption failed: " + err.Error())
	}

	return string(plaintext), nil
}

// HashPassword crea un hash seguro de una contraseña usando Argon2 o bcrypt
// Por defecto usa SHA-256 con salt (para compatibilidad, pero en producción usar Argon2)
func HashPassword(password string) (string, error) {
	// Generar salt aleatorio
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	// Crear hash
	hash := sha256.Sum256(append(salt, []byte(password)...))

	// Devolver salt|hash
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hash[:]), nil
}

// VerifyPassword verifica una contraseña contra un hash almacenado
func VerifyPassword(password, storedHash string) bool {
	// Parsear salt:hash
	parts := splitTwo(storedHash, ":")
	if len(parts) != 2 {
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}

	expectedHash := sha256.Sum256(append(salt, []byte(password)...))
	actualHash := parts[1]

	return hex.EncodeToString(expectedHash[:]) == actualHash
}

// HashToken crea un hash de un token para almacenamiento seguro
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// splitTwo divide un string en dos partes por el separador
func splitTwo(s, sep string) []string {
	idx := index(s, sep)
	if idx == -1 {
		return []string{s, ""}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}

func index(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// GenerateRandomString genera una cadena aleatoria segura
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}

	// Usar base64url
	result := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(result, bytes)

	// Recortar a la longitud deseada
	return string(result[:length]), nil
}

// SecureCompare realiza comparación de tiempo constante para prevenir timing attacks
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}

	return result == 0
}

// EncryptionService interfaz para el servicio de cifrado
type EncryptionService interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// Ensure interface implementation
var _ EncryptionService = (*Encryptor)(nil)
var _ interface{} = (*Encryptor)(nil)
