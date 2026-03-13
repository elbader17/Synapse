# Medical Records Manager - Backend

## Descripción del Proyecto

Backend robusto para gestión de historiales médicos con cumplimiento estricto de HIPAA, GDPR y LGPD.

## Stack Tecnológico

- **Lenguaje**: Go 1.21+
- **Base de Datos**: PostgreSQL 15+
- **Autenticación**: JWT con refresh tokens
- **Cifrado**: AES-256-GCM para datos sensibles en reposo

## Estructura del Proyecto (Clean Architecture)

```
medical-records-manager/
├── cmd/
│   └── api/
│       └── main.go                    # Punto de entrada
├── internal/
│   ├── config/
│   │   └── config.go                  # Configuración centralizada
│   ├── domain/
│   │   ├── entities/
│   │   │   ├── user.go                # Entidad Usuario
│   │   │   ├── patient.go             # Entidad Paciente
│   │   │   ├── medical_record.go      # Entidad Historial Médico
│   │   │   └── audit_log.go           # Entidad Audit Log
│   │   ├── repositories/
│   │   │   ├── user_repository.go     # Interfaz repositorio usuario
│   │   │   ├── patient_repository.go  # Interfaz repositorio paciente
│   │   │   ├── medical_record_repository.go
│   │   │   └── audit_repository.go    # Interfaz repositorio auditoría
│   │   └── services/
│   │       ├── auth_service.go        # Servicio de autenticación
│   │       ├── patient_service.go     # Servicio de pacientes
│   │       ├── medical_record_service.go
│   │       └── audit_service.go       # Servicio de auditoría
│   ├── infrastructure/
│   │   ├── database/
│   │   │   ├── postgres.go            # Conexión PostgreSQL
│   │   │   ├── migrations/            # Migraciones SQL
│   │   │   └── repositories/
│   │   │       ├── user_repo.go
│   │   │       ├── patient_repo.go
│   │   │       ├── medical_record_repo.go
│   │   │       └── audit_repo.go
│   │   ├── crypto/
│   │   │   └── encryption.go         # Cifrado AES-256-GCM
│   │   ├── auth/
│   │   │   ├── jwt.go                # Manejo JWT
│   │   │   └── middleware.go         # Middleware de autenticación
│   │   └── logging/
│   │       └── audit_logger.go       # Logger de auditoría
│   ├── transport/
│   │   ├── handlers/
│   │   │   ├── auth_handler.go
│   │   │   ├── patient_handler.go
│   │   │   ├── medical_record_handler.go
│   │   │   └── health_handler.go
│   │   ├── middleware/
│   │   │   ├── audit_middleware.go   # Middleware de auditoría
│   │   │   ├── cors.go
│   │   │   ├── rate_limiter.go
│   │   │   └── security.go           # Headers de seguridad
│   │   └── router/
│   │       └── router.go             # Configuración de rutas
│   └── utils/
│       ├── errors/
│       │   └── errors.go             # Manejo de errores
│       ├── validators/
│       │   └── validators.go         # Validaciones
│       └── response/
│           └── response.go           # Respuestas API
├── pkg/
│   └── constants/
│       └── constants.go              # Constantes globales
├── docker-compose.yml                 # Docker para desarrollo
├── Dockerfile                        # Imagen Docker
├── go.mod
├── go.sum
└── .env.example                      # Variables de entorno de ejemplo
```

## Principios de Diseño

1. **Separación de intereses**: Cada capa tiene responsabilidad única
2. **Inversión de dependencias**: Las capas internas no dependen de las externas
3. **Minimización de datos**: PII separado de datos clínicos
4. **Trazabilidad total**: Cada operación queda registrada

## Configuración de Variables de Entorno

Ver `.env.example` para las variables requeridas.