package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"medical-records-manager/internal/config"
	"medical-records-manager/internal/infrastructure/crypto"
	"medical-records-manager/internal/infrastructure/database/repositories"
	"medical-records-manager/internal/infrastructure/logging"
	"medical-records-manager/internal/transport/handlers"
	"medical-records-manager/internal/transport/middleware"
	"medical-records-manager/internal/transport/router"
)

func main() {
	// Cargar configuración
	cfg := config.Load()

	// Configurar modo de Gin según el entorno
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Inicializar base de datos
	ctx := context.Background()
	pool, err := initDatabase(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer pool.Close()

	// Verificar conexión a la base de datos
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Database connection established")

	// Inicializar cifrado
	encryptor, err := crypto.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize encryption: %v", err)
	}
	log.Println("Encryption service initialized")

	// Inicializar logger de auditoría
	auditLogger := logging.NewAuditLogger(1000, 4)
	defer auditLogger.Shutdown()
	log.Println("Audit logger initialized")

	// Inicializar repositorios
	medicalRecordRepo := repositories.NewPostgresMedicalRecordRepository(pool)

	// Inicializar handlers
	healthHandler := handlers.NewHealthHandler()
	medicalRecordHandler := handlers.NewMedicalRecordHandler(medicalRecordRepo, encryptor, auditLogger, cfg)

	// Crear router
	r := router.SetupRouter(cfg, auditLogger, healthHandler, medicalRecordHandler, pool)

	// Middleware de seguridad
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.RateLimitMiddleware(cfg.RateLimit))

	// Middleware de auditoría
	r.Use(logging.AuditMiddleware(auditLogger, cfg))

	// Server
	srv := &http.Server{
		Addr:         cfg.ServerHost + ":" + cfg.ServerPort,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Iniciar servidor en goroutine
	go func() {
		log.Printf("Server starting on %s:%s", cfg.ServerHost, cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Esperar señal de shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown con timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func initDatabase(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	// Configuración del pool de conexiones
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Configuración de conexiones
	poolConfig.MaxConns = 25
	poolConfig.MinConns = 5
	poolConfig.MaxConnLifetime = time.Hour
	poolConfig.MaxConnIdleTime = 30 * time.Minute

	// Crear pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	return pool, nil
}
