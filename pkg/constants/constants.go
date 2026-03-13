package constants

// User Roles - RBAC
const (
	RoleAdmin        = "admin"        // Administrador del sistema
	RoleDoctor       = "doctor"       // Médico tratante
	RoleNurse        = "nurse"        // Enfermero
	RoleReceptionist = "receptionist" // Recepcionista
	RolePatient      = "patient"      // Paciente (acceso limitado a sus propios datos)
)

// Resource Types - Para auditoría
const (
	ResourceUser          = "user"
	ResourcePatient       = "patient"
	ResourceMedicalRecord = "medical_record"
	ResourceAuditLog      = "audit_log"
	ResourceAuth          = "auth"
)

// Action Types - Para auditoría
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionLogin  = "login"
	ActionLogout = "logout"
	ActionFailed = "failed_attempt"
	ActionExport = "export"
)

// Audit Event Types
const (
	EventUserLogin        = "USER_LOGIN"
	EventUserLogout       = "USER_LOGOUT"
	EventUserCreate       = "USER_CREATE"
	EventUserUpdate       = "USER_UPDATE"
	EventUserDelete       = "USER_DELETE"
	EventPatientCreate    = "PATIENT_CREATE"
	EventPatientUpdate    = "PATIENT_UPDATE"
	EventPatientDelete    = "PATIENT_DELETE"
	EventRecordCreate     = "RECORD_CREATE"
	EventRecordRead       = "RECORD_READ"
	EventRecordUpdate     = "RECORD_UPDATE"
	EventRecordDelete     = "RECORD_DELETE"
	EventRecordExport     = "RECORD_EXPORT"
	EventAccessDenied     = "ACCESS_DENIED"
	EventDataModification = "DATA_MODIFICATION"
)

// Medical Record Types
const (
	RecordTypeConsultation = "consultation"
	RecordTypeDiagnosis    = "diagnosis"
	RecordTypePrescription = "prescription"
	RecordTypeLabResult    = "lab_result"
	RecordTypeProcedure    = "procedure"
	RecordTypeImaging      = "imaging"
	RecordTypeNote         = "note"
)

// Sensitive Fields - Para cifrado
var SensitivePatientFields = []string{
	"ssn",
	"full_name",
	"address",
	"phone",
	"email",
	"emergency_contact",
	"insurance_number",
}

var SensitiveMedicalRecordFields = []string{
	"diagnosis",
	"notes",
	"prescription_details",
	"lab_results",
}

// Validation Rules
const (
	MinPasswordLength    = 12
	MaxNameLength        = 100
	MaxAddressLength     = 500
	MinSSNLength         = 9
	MaxSSNLength         = 11
	MaxMedicalNoteLength = 10000
)

// GDPR/LGPD Rights
const (
	RightAccess        = "access"        // Derecho de acceso
	RightRectification = "rectification" // Derecho de rectificación
	RightErasure       = "erasure"       // Derecho al olvido (restringido para HIPAA)
	RightPortability   = "portability"   // Derecho a la portabilidad
	RightRestriction   = "restriction"   // Derecho a la restricción
)

// HIPAA Retention (minimum 6 years for most records)
const HIPAARetentionYears = 6
const HIPAARetentionDays = HIPAARetentionYears * 365
