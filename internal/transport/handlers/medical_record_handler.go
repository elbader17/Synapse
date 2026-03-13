package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"medical-records-manager/internal/config"
	"medical-records-manager/internal/domain/entities"
	"medical-records-manager/internal/domain/repositories"
	"medical-records-manager/internal/infrastructure/crypto"
	"medical-records-manager/internal/infrastructure/logging"
	"medical-records-manager/pkg/constants"
)

// MedicalRecordHandler maneja las solicitudes de registros médicos
type MedicalRecordHandler struct {
	repo        repositories.MedicalRecordRepository
	encryptor   crypto.EncryptionService
	auditLogger *logging.AuditLogger
	cfg         *config.Config
}

// NewMedicalRecordHandler crea un nuevo MedicalRecordHandler
func NewMedicalRecordHandler(
	repo repositories.MedicalRecordRepository,
	encryptor crypto.EncryptionService,
	auditLogger *logging.AuditLogger,
	cfg *config.Config,
) *MedicalRecordHandler {
	return &MedicalRecordHandler{
		repo:        repo,
		encryptor:   encryptor,
		auditLogger: auditLogger,
		cfg:         cfg,
	}
}

// Create crea un nuevo registro médico
func (h *MedicalRecordHandler) Create(c *gin.Context) {
	var req entities.CreateMedicalRecordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Obtener ID del usuario del contexto (del JWT middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parsear fecha de visita
	visitDate, err := time.Parse("2006-01-02", req.VisitDate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid visit date format, use YYYY-MM-DD"})
		return
	}

	// Cifrar contenido del registro médico
	encryptedContent, err := h.encryptor.Encrypt(req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt medical record"})
		return
	}

	// Crear registro
	record := &entities.MedicalRecord{
		PatientID:        req.PatientID,
		RecordType:       req.RecordType,
		EncryptedContent: encryptedContent,
		ProviderID:       userID.(string),
		VisitDate:        visitDate,
		IsConfidential:   req.IsConfidential,
		FacilityID:       "default-facility", // En producción, obtener del contexto
	}

	if err := h.repo.Create(c.Request.Context(), record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create medical record"})
		return
	}

	// Registrar en auditoría
	h.auditLogger.LogRecordModification(
		c.Request.Context(),
		userID.(string),
		"doctor", // En producción, obtener del contexto
		record.ID,
		req.PatientID,
		logging.GetClientIP(c),
		c.Request.UserAgent(),
		constants.ActionCreate,
	)

	c.JSON(http.StatusCreated, gin.H{
		"message": "Medical record created successfully",
		"id":      record.ID,
	})
}

// GetByPatientID obtiene todos los registros de un paciente
func (h *MedicalRecordHandler) GetByPatientID(c *gin.Context) {
	patientID := c.Param("patientID")
	if patientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Patient ID is required"})
		return
	}

	// Validar UUID
	if _, err := uuid.Parse(patientID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid patient ID format"})
		return
	}

	// Parsear parámetros de paginación
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 100 {
		limit = 100 // Máximo permitido
	}

	// Obtener registros
	records, err := h.repo.GetByPatientID(c.Request.Context(), patientID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve medical records"})
		return
	}

	// Descifrar contenido para cada registro
	type RecordResponse struct {
		ID             string    `json:"id"`
		PatientID      string    `json:"patient_id"`
		RecordType     string    `json:"record_type"`
		Content        string    `json:"content"`
		ProviderID     string    `json:"provider_id"`
		FacilityID     string    `json:"facility_id"`
		VisitDate      time.Time `json:"visit_date"`
		IsConfidential bool      `json:"is_confidential"`
		CreatedAt      time.Time `json:"created_at"`
		UpdatedAt      time.Time `json:"updated_at"`
	}

	var response []RecordResponse
	for _, record := range records {
		content, _ := h.encryptor.Decrypt(record.EncryptedContent)
		response = append(response, RecordResponse{
			ID:             record.ID,
			PatientID:      record.PatientID,
			RecordType:     record.RecordType,
			Content:        content,
			ProviderID:     record.ProviderID,
			FacilityID:     record.FacilityID,
			VisitDate:      record.VisitDate,
			IsConfidential: record.IsConfidential,
			CreatedAt:      record.CreatedAt,
			UpdatedAt:      record.UpdatedAt,
		})
	}

	// Registrar acceso en auditoría
	userID, _ := c.Get("user_id")
	if userID != nil {
		h.auditLogger.LogAccessToPatient(
			c.Request.Context(),
			userID.(string),
			"doctor",
			patientID,
			logging.GetClientIP(c),
			c.Request.UserAgent(),
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"records": response,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetByID obtiene un registro médico específico
func (h *MedicalRecordHandler) GetByID(c *gin.Context) {
	recordID := c.Param("id")
	if recordID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record ID is required"})
		return
	}

	// Validar UUID
	if _, err := uuid.Parse(recordID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid record ID format"})
		return
	}

	// Obtener registro
	record, err := h.repo.GetByID(c.Request.Context(), recordID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve medical record"})
		return
	}

	if record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Medical record not found"})
		return
	}

	// Descifrar contenido
	content, _ := h.encryptor.Decrypt(record.EncryptedContent)

	c.JSON(http.StatusOK, gin.H{
		"id":              record.ID,
		"patient_id":      record.PatientID,
		"record_type":     record.RecordType,
		"content":         content,
		"provider_id":     record.ProviderID,
		"facility_id":     record.FacilityID,
		"visit_date":      record.VisitDate,
		"is_confidential": record.IsConfidential,
		"created_at":      record.CreatedAt,
		"updated_at":      record.UpdatedAt,
	})
}

// Delete realiza un soft delete de un registro médico
func (h *MedicalRecordHandler) Delete(c *gin.Context) {
	recordID := c.Param("id")
	if recordID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Record ID is required"})
		return
	}

	// Validar UUID
	if _, err := uuid.Parse(recordID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid record ID format"})
		return
	}

	// Obtener usuario
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Obtener registro para auditoría
	record, err := h.repo.GetByID(c.Request.Context(), recordID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve medical record"})
		return
	}

	if record == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Medical record not found"})
		return
	}

	// Realizar soft delete
	if err := h.repo.SoftDelete(c.Request.Context(), recordID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete medical record"})
		return
	}

	// Registrar en auditoría
	h.auditLogger.LogRecordModification(
		c.Request.Context(),
		userID.(string),
		"doctor",
		recordID,
		record.PatientID,
		logging.GetClientIP(c),
		c.Request.UserAgent(),
		constants.ActionDelete,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Medical record deleted successfully"})
}
