package repositories

import (
	"context"
	"time"

	"medical-records-manager/internal/domain/entities"
)

// MedicalRecordRepository define la interfaz para el repositorio de registros médicos
type MedicalRecordRepository interface {
	// Create crea un nuevo registro médico
	Create(ctx context.Context, record *entities.MedicalRecord) error

	// GetByID obtiene un registro médico por su ID
	GetByID(ctx context.Context, id string) (*entities.MedicalRecord, error)

	// GetByPatientID obtiene todos los registros de un paciente
	GetByPatientID(ctx context.Context, patientID string, limit, offset int) ([]entities.MedicalRecord, error)

	// Update actualiza un registro médico
	Update(ctx context.Context, record *entities.MedicalRecord) error

	// SoftDelete realiza un borrado lógico
	SoftDelete(ctx context.Context, id string) error

	// GetByDateRange obtiene registros en un rango de fechas
	GetByDateRange(ctx context.Context, patientID string, start, end time.Time) ([]entities.MedicalRecord, error)

	// GetByType obtiene registros por tipo
	GetByType(ctx context.Context, patientID, recordType string) ([]entities.MedicalRecord, error)
}
