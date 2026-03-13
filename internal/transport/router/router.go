package router

import (
	"github.com/gin-gonic/gin"

	"medical-records-manager/internal/config"
	"medical-records-manager/internal/infrastructure/auth"
	"medical-records-manager/internal/infrastructure/crypto"
	"medical-records-manager/internal/infrastructure/database/repositories"
	"medical-records-manager/internal/infrastructure/logging"
	"medical-records-manager/internal/transport/handlers"
	"medical-records-manager/internal/transport/middleware"
	"medical-records-manager/pkg/constants"
)

// SetupRouter configura todas las rutas de la API
func SetupRouter(
	cfg *config.Config,
	auditLogger *logging.AuditLogger,
	healthHandler *handlers.HealthHandler,
	medicalRecordHandler *handlers.MedicalRecordHandler,
	pool interface { /* pgxpool.Pool */
	},
) *gin.Engine {
	r := gin.Default()

	// Rutas públicas - Health check
	r.GET("/health", healthHandler.Health)
	r.GET("/ready", healthHandler.Ready)

	// ============================================================
	// INICIALIZAR SERVICIOS
	// ============================================================

	// Cifrado
	encryptor, _ := crypto.NewEncryptor(cfg.EncryptionKey)

	// Auth Service
	authService := auth.NewAuthService(cfg, encryptor, auditLogger)

	// Handlers
	authHandler := handlers.NewAuthHandler(authService)
	_ = repositories.NewPostgresUserRepository(nil) // Para uso futuro

	// ============================================================
	// GRUPO DE API v1
	// ============================================================

	v1 := r.Group("/api/v1")
	{
		// ----------------------------------------
		// RUTAS PÚBLICAS (sin autenticación)
		// ----------------------------------------

		// Auth - Login (público)
		auth := v1.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.POST("/password-requirements", authHandler.GetPasswordRequirements)
		}

		// ----------------------------------------
		// RUTAS PROTEGIDAS (requieren JWT)
		// ----------------------------------------

		protected := v1.Group("")
		protected.Use(middleware.RequireAuth())
		{
			// ---- Auth (protegido) ----
			authProtected := protected.Group("/auth")
			{
				// Verificar 2FA
				authProtected.POST("/verify-2fa", authHandler.Verify2FA)

				// 2FA Management
				authProtected.POST("/2fa/setup", authHandler.Setup2FA)
				authProtected.POST("/2fa/verify", authHandler.Verify2FASetup)
				authProtected.POST("/2fa/disable", authHandler.Disable2FA)

				// Password management
				authProtected.POST("/change-password", authHandler.ChangePassword)
				authProtected.POST("/refresh", authHandler.RefreshToken)
				authProtected.POST("/logout", authHandler.Logout)
			}

			// ---- Users (solo admin) ----
			users := protected.Group("/users")
			users.Use(middleware.RequireRole(constants.RoleAdmin))
			{
				// users.GET("", userHandler.List)
				// users.POST("", userHandler.Create)
				// users.GET("/:id", userHandler.GetByID)
				// users.PUT("/:id", userHandler.Update)
				// users.DELETE("/:id", userHandler.Delete)
			}

			// ---- Patients ----
			patients := protected.Group("/patients")
			patients.Use(middleware.RequireRole(constants.RoleAdmin, constants.RoleDoctor, constants.RoleNurse, constants.RoleReceptionist))
			{
				// patients.GET("", patientHandler.List)
				// patients.POST("", patientHandler.Create)
				// patients.GET("/:id", patientHandler.GetByID)
				// patients.PUT("/:id", patientHandler.Update)
				// patients.DELETE("/:id", patientHandler.Delete)
			}

			// ---- Medical Records ----
			records := protected.Group("/medical-records")
			records.Use(middleware.RequireRole(constants.RoleAdmin, constants.RoleDoctor, constants.RoleNurse))
			{
				records.POST("", medicalRecordHandler.Create)
				records.GET("/patient/:patientID", medicalRecordHandler.GetByPatientID)
				records.GET("/:id", medicalRecordHandler.GetByID)
				records.DELETE("/:id", medicalRecordHandler.Delete)
			}

			// ---- Audit Logs (solo admin) ----
			audit := protected.Group("/audit-logs")
			audit.Use(middleware.RequireRole(constants.RoleAdmin))
			{
				// audit.GET("", auditHandler.List)
				// audit.GET("/:id", auditHandler.GetByID)
			}
		}
	}

	// Manejo de 404
	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{
			"error": "Endpoint not found",
		})
	})

	return r
}
