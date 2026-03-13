package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"medical-records-manager/internal/domain/entities"
	"medical-records-manager/internal/domain/repositories"
)

// PostgresMedicalRecordRepository implementa MedicalRecordRepository para PostgreSQL
type PostgresMedicalRecordRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresMedicalRecordRepository crea una nueva instancia del repositorio
func NewPostgresMedicalRecordRepository(pool *pgxpool.Pool) *PostgresMedicalRecordRepository {
	return &PostgresMedicalRecordRepository{pool: pool}
}

// Create crea un nuevo registro médico
func (r *PostgresMedicalRecordRepository) Create(ctx context.Context, record *entities.MedicalRecord) error {
	if record.ID == "" {
		record.ID = uuid.New().String()
	}
	record.CreatedAt = time.Now().UTC()
	record.UpdatedAt = time.Now().UTC()

	query := `
		INSERT INTO medical_records (
			id, patient_id, record_type, encrypted_content,
			provider_id, facility_id, visit_date, is_confidential,
			is_active, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, true, $9, $10
		)
	`

	_, err := r.pool.Exec(ctx, query,
		record.ID,
		record.PatientID,
		record.RecordType,
		record.EncryptedContent,
		record.ProviderID,
		record.FacilityID,
		record.VisitDate,
		record.IsConfidential,
		record.CreatedAt,
		record.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create medical record: %w", err)
	}

	return nil
}

// GetByID obtiene un registro médico por su ID
func (r *PostgresMedicalRecordRepository) GetByID(ctx context.Context, id string) (*entities.MedicalRecord, error) {
	query := `
		SELECT id, patient_id, record_type, encrypted_content,
		       provider_id, facility_id, visit_date, is_confidential,
		       is_active, created_at, updated_at, deleted_at
		FROM medical_records
		WHERE id = $1 AND is_active = true
	`

	var record entities.MedicalRecord
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&record.ID,
		&record.PatientID,
		&record.RecordType,
		&record.EncryptedContent,
		&record.ProviderID,
		&record.FacilityID,
		&record.VisitDate,
		&record.IsConfidential,
		&record.IsActive,
		&record.CreatedAt,
		&record.UpdatedAt,
		&record.DeletedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get medical record: %w", err)
	}

	return &record, nil
}

// GetByPatientID obtiene todos los registros activos de un paciente
func (r *PostgresMedicalRecordRepository) GetByPatientID(ctx context.Context, patientID string, limit, offset int) ([]entities.MedicalRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, patient_id, record_type, encrypted_content,
		       provider_id, facility_id, visit_date, is_confidential,
		       is_active, created_at, updated_at, deleted_at
		FROM medical_records
		WHERE patient_id = $1 AND is_active = true
		ORDER BY visit_date DESC, created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, patientID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get medical records: %w", err)
	}
	defer rows.Close()

	var records []entities.MedicalRecord
	for rows.Next() {
		var record entities.MedicalRecord
		err := rows.Scan(
			&record.ID,
			&record.PatientID,
			&record.RecordType,
			&record.EncryptedContent,
			&record.ProviderID,
			&record.FacilityID,
			&record.VisitDate,
			&record.IsConfidential,
			&record.IsActive,
			&record.CreatedAt,
			&record.UpdatedAt,
			&record.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan medical record: %w", err)
		}
		records = append(records, record)
	}

	return records, nil
}

// Update actualiza un registro médico
func (r *PostgresMedicalRecordRepository) Update(ctx context.Context, record *entities.MedicalRecord) error {
	record.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE medical_records
		SET record_type = $2,
		    encrypted_content = $3,
		    facility_id = $4,
		    visit_date = $5,
		    is_confidential = $6,
		    updated_at = $7
		WHERE id = $1 AND is_active = true
	`

	result, err := r.pool.Exec(ctx, query,
		record.ID,
		record.RecordType,
		record.EncryptedContent,
		record.FacilityID,
		record.VisitDate,
		record.IsConfidential,
		record.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update medical record: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("medical record not found or already deleted")
	}

	return nil
}

// SoftDelete realiza un borrado lógico ( HIPAA compliance )
func (r *PostgresMedicalRecordRepository) SoftDelete(ctx context.Context, id string) error {
	query := `
		UPDATE medical_records
		SET is_active = false, deleted_at = $2
		WHERE id = $1 AND is_active = true
	`

	result, err := r.pool.Exec(ctx, query, id, time.Now().UTC())

	if err != nil {
		return fmt.Errorf("failed to soft delete medical record: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("medical record not found or already deleted")
	}

	return nil
}

// GetByDateRange obtiene registros en un rango de fechas
func (r *PostgresMedicalRecordRepository) GetByDateRange(ctx context.Context, patientID string, start, end time.Time) ([]entities.MedicalRecord, error) {
	query := `
		SELECT id, patient_id, record_type, encrypted_content,
		       provider_id, facility_id, visit_date, is_confidential,
		       is_active, created_at, updated_at, deleted_at
		FROM medical_records
		WHERE patient_id = $1 
		  AND visit_date >= $2 
		  AND visit_date <= $3
		  AND is_active = true
		ORDER BY visit_date DESC
	`

	rows, err := r.pool.Query(ctx, query, patientID, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get medical records by date range: %w", err)
	}
	defer rows.Close()

	var records []entities.MedicalRecord
	for rows.Next() {
		var record entities.MedicalRecord
		err := rows.Scan(
			&record.ID,
			&record.PatientID,
			&record.RecordType,
			&record.EncryptedContent,
			&record.ProviderID,
			&record.FacilityID,
			&record.VisitDate,
			&record.IsConfidential,
			&record.IsActive,
			&record.CreatedAt,
			&record.UpdatedAt,
			&record.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan medical record: %w", err)
		}
		records = append(records, record)
	}

	return records, nil
}

// GetByType obtiene registros por tipo
func (r *PostgresMedicalRecordRepository) GetByType(ctx context.Context, patientID, recordType string) ([]entities.MedicalRecord, error) {
	query := `
		SELECT id, patient_id, record_type, encrypted_content,
		       provider_id, facility_id, visit_date, is_confidential,
		       is_active, created_at, updated_at, deleted_at
		FROM medical_records
		WHERE patient_id = $1 
		  AND record_type = $2
		  AND is_active = true
		ORDER BY visit_date DESC
	`

	rows, err := r.pool.Query(ctx, query, patientID, recordType)
	if err != nil {
		return nil, fmt.Errorf("failed to get medical records by type: %w", err)
	}
	defer rows.Close()

	var records []entities.MedicalRecord
	for rows.Next() {
		var record entities.MedicalRecord
		err := rows.Scan(
			&record.ID,
			&record.PatientID,
			&record.RecordType,
			&record.EncryptedContent,
			&record.ProviderID,
			&record.FacilityID,
			&record.VisitDate,
			&record.IsConfidential,
			&record.IsActive,
			&record.CreatedAt,
			&record.UpdatedAt,
			&record.DeletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan medical record: %w", err)
		}
		records = append(records, record)
	}

	return records, nil
}

// Ensure interface implementation
var _ repositories.MedicalRecordRepository = (*PostgresMedicalRecordRepository)(nil)
var _ interface{} = (*PostgresMedicalRecordRepository)(nil)
