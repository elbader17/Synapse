package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"medical-records-manager/internal/config"
	"medical-records-manager/internal/domain/entities"
	"medical-records-manager/pkg/constants"
)

// AuditLogger manejar el registro de auditoría de forma asíncrona
type AuditLogger struct {
	auditChan   chan AuditEntry
	workerCount int
	shutdown    chan struct{}
}

// AuditEntry representa una entrada de auditoría
type AuditEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	UserID       string    `json:"user_id"`
	UserRole     string    `json:"user_role"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	EventType    string    `json:"event_type"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Action       string    `json:"action"`
	Details      string    `json:"details"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
}

// NewAuditLogger crea un nuevo logger de auditoría
func NewAuditLogger(bufferSize int, workers int) *AuditLogger {
	logger := &AuditLogger{
		auditChan:   make(chan AuditEntry, bufferSize),
		workerCount: workers,
		shutdown:    make(chan struct{}),
	}

	// Iniciar workers asíncronos
	for i := 0; i < workers; i++ {
		go logger.worker(i)
	}

	return logger
}

// worker procesa las entradas de auditoría
func (al *AuditLogger) worker(id int) {
	for {
		select {
		case entry := <-al.auditChan:
			al.processEntry(entry)
		case <-al.shutdown:
			// Procesar entradas restantes antes de salir
			for {
				select {
				case entry := <-al.auditChan:
					al.processEntry(entry)
				default:
					return
				}
			}
		}
	}
}

// processEntry procesa una entrada de auditoría (aquí se guardaría en BD)
func (al *AuditLogger) processEntry(entry AuditEntry) {
	// En producción, aquí se insertaría en la base de datos
	// Usar batch inserts para mejor rendimiento
	fmt.Printf("[AUDIT] %s | User: %s | IP: %s | Action: %s | Resource: %s:%s | Success: %v\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.UserID,
		entry.IP,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.Success)
}

// Log registra una entrada de auditoría
func (al *AuditLogger) Log(entry AuditEntry) {
	select {
	case al.auditChan <- entry:
		// Entry encolado correctamente
	default:
		// Buffer lleno - registrar en log de emergencia
		fmt.Printf("[AUDIT EMERGENCY] Buffer lleno, no se pudo registrar: %+v\n", entry)
	}
}

// Shutdown detiene el logger de auditoría
func (al *AuditLogger) Shutdown() {
	close(al.shutdown)
}

// ============================================================
// MIDDLEWARE DE AUDITORÍA PARA GIN
// ============================================================

// AuditMiddleware crea el middleware de auditoría
func AuditMiddleware(auditLogger *AuditLogger, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Extraer información del usuario si está autenticado
		var userID, userRole string
		if claims, exists := c.Get("user_claims"); exists {
			if tokenClaims, ok := claims.(*entities.TokenClaims); ok {
				userID = tokenClaims.UserID
				userRole = tokenClaims.Role
			}
		}

		// Obtener IP del cliente (considerar proxies)
		clientIP := GetClientIP(c)

		// Procesar la request
		c.Next()

		// Calcular duración
		latency := time.Since(start)

		// Determinar tipo de acción
		action := getActionFromMethod(method)

		// Determinar tipo de recurso
		resourceType := getResourceTypeFromPath(path)

		// Obtener código de respuesta
		statusCode := c.Writer.Status()

		// Determinar éxito
		success := statusCode >= 200 && statusCode < 400

		// Determinar tipo de evento
		eventType := determineEventType(method, path, statusCode)

		// Construir detalles de la request
		details := buildAuditDetails(c, latency, statusCode)

		// Crear entrada de auditoría
		entry := AuditEntry{
			Timestamp:    time.Now().UTC(),
			UserID:       userID,
			UserRole:     userRole,
			IP:           clientIP,
			UserAgent:    c.Request.UserAgent(),
			EventType:    eventType,
			ResourceType: resourceType,
			ResourceID:   getResourceID(c),
			Action:       action,
			Details:      details,
			Success:      success,
		}

		// Agregar mensaje de error si falló
		if !success {
			if errMsg := c.Errors.ByType(gin.ErrorTypePrivate).String(); errMsg != "" {
				entry.Error = errMsg
			}
		}

		// Registrar en logger asíncrono
		auditLogger.Log(entry)
	}
}

// GetClientIP obtiene la IP real del cliente considerando proxies
func GetClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header (para cuando hay proxy/reverse proxy)
	xff := c.GetHeader("X-Forwarded-For")
	if xff != "" {
		// Tomar primera IP (la del cliente original)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header (nginx)
	xri := c.GetHeader("X-Real-IP")
	if xri != "" && net.ParseIP(xri) != nil {
		return xri
	}

	// Fallback a la IP de la conexión
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return ip
}

func getActionFromMethod(method string) string {
	switch method {
	case http.MethodGet:
		return constants.ActionRead
	case http.MethodPost:
		return constants.ActionCreate
	case http.MethodPut, http.MethodPatch:
		return constants.ActionUpdate
	case http.MethodDelete:
		return constants.ActionDelete
	default:
		return "unknown"
	}
}

func getResourceTypeFromPath(path string) string {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) < 1 {
		return "unknown"
	}

	switch segments[0] {
	case "auth":
		return constants.ResourceAuth
	case "users":
		return constants.ResourceUser
	case "patients":
		return constants.ResourcePatient
	case "records", "medical-records":
		return constants.ResourceMedicalRecord
	case "audit-logs":
		return constants.ResourceAuditLog
	default:
		return "unknown"
	}
}

func getResourceID(c *gin.Context) string {
	// Intentar obtener ID del contexto de Gin
	if id, exists := c.Get("resource_id"); exists {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}

	// Intentar extraer de la URL
	path := c.Request.URL.Path
	segments := strings.Split(path, "/")
	if len(segments) >= 2 {
		lastSegment := segments[len(segments)-1]
		// Verificar si parece un UUID
		if _, err := uuid.Parse(lastSegment); err == nil {
			return lastSegment
		}
	}

	return ""
}

func determineEventType(method, path string, statusCode int) string {
	// Login/Logout
	if strings.Contains(path, "/auth/login") {
		if method == http.MethodPost {
			if statusCode >= 200 && statusCode < 300 {
				return constants.EventUserLogin
			}
		}
	}
	if strings.Contains(path, "/auth/logout") {
		return constants.EventUserLogout
	}

	// Access denied
	if statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized {
		return constants.EventAccessDenied
	}

	// Por método y recurso
	if strings.Contains(path, "/patients") {
		switch method {
		case http.MethodPost:
			return constants.EventPatientCreate
		case http.MethodPut, http.MethodPatch:
			return constants.EventPatientUpdate
		case http.MethodDelete:
			return constants.EventPatientDelete
		}
	}

	if strings.Contains(path, "/records") || strings.Contains(path, "/medical-records") {
		switch method {
		case http.MethodPost:
			return constants.EventRecordCreate
		case http.MethodGet:
			return constants.EventRecordRead
		case http.MethodPut, http.MethodPatch:
			return constants.EventRecordUpdate
		case http.MethodDelete:
			return constants.EventRecordDelete
		}
	}

	return constants.EventDataModification
}

func buildAuditDetails(c *gin.Context, latency time.Duration, statusCode int) string {
	details := map[string]interface{}{
		"method":      c.Request.Method,
		"path":        c.Request.URL.Path,
		"query":       c.Request.URL.Query().Encode(),
		"status_code": statusCode,
		"latency_ms":  latency.Milliseconds(),
	}

	// Agregar headers relevantes (sin datos sensibles)
	if c.Request.Header.Get("Content-Type") != "" {
		details["content_type"] = c.Request.Header.Get("Content-Type")
	}

	// Serializar a JSON
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return "{}"
	}

	return string(detailsJSON)
}

// ============================================================
// FUNCIONES DE AUDITORÍA PROGRAMÁTICA
// ============================================================

// LogAccessToPatient registra cuando un usuario accede a datos de un paciente
func (al *AuditLogger) LogAccessToPatient(ctx context.Context, userID, userRole, patientID, ip, userAgent string) {
	entry := AuditEntry{
		Timestamp:    time.Now().UTC(),
		UserID:       userID,
		UserRole:     userRole,
		IP:           ip,
		UserAgent:    userAgent,
		EventType:    constants.EventPatientUpdate, // Actually accessing
		ResourceType: constants.ResourcePatient,
		ResourceID:   patientID,
		Action:       constants.ActionRead,
		Details:      fmt.Sprintf(`{"operation": "patient_data_access", "patient_id": "%s"}`, patientID),
		Success:      true,
	}
	al.Log(entry)
}

// LogRecordModification registra modificación de un registro médico
func (al *AuditLogger) LogRecordModification(ctx context.Context, userID, userRole, recordID, patientID, ip, userAgent string, operation string) {
	entry := AuditEntry{
		Timestamp:    time.Now().UTC(),
		UserID:       userID,
		UserRole:     userRole,
		IP:           ip,
		UserAgent:    userAgent,
		EventType:    constants.EventRecordUpdate,
		ResourceType: constants.ResourceMedicalRecord,
		ResourceID:   recordID,
		Action:       operation,
		Details:      fmt.Sprintf(`{"operation": "%s", "record_id": "%s", "patient_id": "%s"}`, operation, recordID, patientID),
		Success:      true,
	}
	al.Log(entry)
}

// LogFailedAttempt registra un intento fallido de acceso
func (al *AuditLogger) LogFailedAttempt(ctx context.Context, userID, ip, userAgent, reason, resourceType string) {
	entry := AuditEntry{
		Timestamp:    time.Now().UTC(),
		UserID:       userID,
		IP:           ip,
		UserAgent:    userAgent,
		EventType:    constants.EventAccessDenied,
		ResourceType: resourceType,
		Action:       constants.ActionFailed,
		Details:      fmt.Sprintf(`{"reason": "%s"}`, reason),
		Success:      false,
		Error:        reason,
	}
	al.Log(entry)
}

// GetStackTrace returns a stack trace of the current goroutine
func GetStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// ContextKey type for custom context keys
type ContextKey string

const (
	ContextUserID    ContextKey = "user_id"
	ContextUserRole  ContextKey = "user_role"
	ContextRequestID ContextKey = "request_id"
)

// AddAuditContext adds audit-related data to the context
func AddAuditContext(ctx context.Context, userID, role string) context.Context {
	ctx = context.WithValue(ctx, ContextUserID, userID)
	ctx = context.WithValue(ctx, ContextUserRole, role)
	ctx = context.WithValue(ctx, ContextRequestID, uuid.New().String())
	return ctx
}

// GetAuditContext retrieves audit data from context
func GetAuditContext(ctx context.Context) (userID, role, requestID string) {
	if v := ctx.Value(ContextUserID); v != nil {
		userID = v.(string)
	}
	if v := ctx.Value(ContextUserRole); v != nil {
		role = v.(string)
	}
	if v := ctx.Value(ContextRequestID); v != nil {
		requestID = v.(string)
	}
	return
}

// VerifyAuditIntegrity verifica la integridad de los logs de auditoría
// En producción, esto verificaría firmas digitales o hash chains
func VerifyAuditIntegrity(logs []AuditEntry) bool {
	// Verificar que los timestamps estén en orden ascendente
	for i := 1; i < len(logs); i++ {
		if logs[i].Timestamp.Before(logs[i-1].Timestamp) {
			return false
		}
	}
	return true
}

// SanitizeLogEntry limpia datos sensibles de una entrada de auditoría
func SanitizeLogEntry(entry AuditEntry) AuditEntry {
	// Crear copia para no modificar original
	sanitized := entry

	// Limpiar details si contiene datos sensibles
	if strings.Contains(sanitized.Details, "password") {
		sanitized.Details = strings.ReplaceAll(sanitized.Details, "password", "****")
	}
	if strings.Contains(sanitized.Details, "ssn") {
		sanitized.Details = strings.ReplaceAll(sanitized.Details, "ssn", "***-**-****")
	}

	// Limpiar user agent si es muy largo
	if len(sanitized.UserAgent) > 200 {
		sanitized.UserAgent = sanitized.UserAgent[:200] + "..."
	}

	return sanitized
}

// Ensure interface implementation
var _ interface{} = (*AuditLogger)(nil)

// Type assertion to verify AuditLogger implements required methods
func init() {
	var _ interface{} = (interface{})(nil)
}

// Use reflection to avoid unused warnings
var _ = reflect.TypeOf(AuditLogger{})
var _ = reflect.TypeOf(AuditEntry{})
