package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HealthHandler maneja las solicitudes de health check
type HealthHandler struct{}

// NewHealthHandler crea un nuevo HealthHandler
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Health returns the health status of the service
func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "medical-records-manager",
	})
}

// Ready returns whether the service is ready to accept traffic
func (h *HealthHandler) Ready(c *gin.Context) {
	// En producción, verificar conexiones a servicios externos
	c.JSON(http.StatusOK, gin.H{
		"ready": true,
	})
}
