// Code generated by ent, DO NOT EDIT.

package finding

import (
	"fmt"
	"io"
	"strconv"

	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the finding type in the database.
	Label = "finding"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldSeverity holds the string denoting the severity field in the database.
	FieldSeverity = "severity"
	// FieldDifficulty holds the string denoting the difficulty field in the database.
	FieldDifficulty = "difficulty"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// EdgeFindingToUser holds the string denoting the findingtouser edge name in mutations.
	EdgeFindingToUser = "FindingToUser"
	// EdgeFindingToHost holds the string denoting the findingtohost edge name in mutations.
	EdgeFindingToHost = "FindingToHost"
	// EdgeFindingToScript holds the string denoting the findingtoscript edge name in mutations.
	EdgeFindingToScript = "FindingToScript"
	// EdgeFindingToEnvironment holds the string denoting the findingtoenvironment edge name in mutations.
	EdgeFindingToEnvironment = "FindingToEnvironment"
	// Table holds the table name of the finding in the database.
	Table = "findings"
	// FindingToUserTable is the table that holds the FindingToUser relation/edge.
	FindingToUserTable = "users"
	// FindingToUserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	FindingToUserInverseTable = "users"
	// FindingToUserColumn is the table column denoting the FindingToUser relation/edge.
	FindingToUserColumn = "finding_finding_to_user"
	// FindingToHostTable is the table that holds the FindingToHost relation/edge.
	FindingToHostTable = "findings"
	// FindingToHostInverseTable is the table name for the Host entity.
	// It exists in this package in order to avoid circular dependency with the "host" package.
	FindingToHostInverseTable = "hosts"
	// FindingToHostColumn is the table column denoting the FindingToHost relation/edge.
	FindingToHostColumn = "finding_finding_to_host"
	// FindingToScriptTable is the table that holds the FindingToScript relation/edge.
	FindingToScriptTable = "findings"
	// FindingToScriptInverseTable is the table name for the Script entity.
	// It exists in this package in order to avoid circular dependency with the "script" package.
	FindingToScriptInverseTable = "scripts"
	// FindingToScriptColumn is the table column denoting the FindingToScript relation/edge.
	FindingToScriptColumn = "script_script_to_finding"
	// FindingToEnvironmentTable is the table that holds the FindingToEnvironment relation/edge.
	FindingToEnvironmentTable = "findings"
	// FindingToEnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	FindingToEnvironmentInverseTable = "environments"
	// FindingToEnvironmentColumn is the table column denoting the FindingToEnvironment relation/edge.
	FindingToEnvironmentColumn = "environment_findings"
)

// Columns holds all SQL columns for finding fields.
var Columns = []string{
	FieldID,
	FieldName,
	FieldDescription,
	FieldSeverity,
	FieldDifficulty,
	FieldTags,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "findings"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_findings",
	"finding_finding_to_host",
	"script_script_to_finding",
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)

// Severity defines the type for the "severity" enum field.
type Severity string

// Severity values.
const (
	SeverityZeroSeverity     Severity = "ZeroSeverity"
	SeverityLowSeverity      Severity = "LowSeverity"
	SeverityMediumSeverity   Severity = "MediumSeverity"
	SeverityHighSeverity     Severity = "HighSeverity"
	SeverityCriticalSeverity Severity = "CriticalSeverity"
	SeverityNullSeverity     Severity = "NullSeverity"
)

func (s Severity) String() string {
	return string(s)
}

// SeverityValidator is a validator for the "severity" field enum values. It is called by the builders before save.
func SeverityValidator(s Severity) error {
	switch s {
	case SeverityZeroSeverity, SeverityLowSeverity, SeverityMediumSeverity, SeverityHighSeverity, SeverityCriticalSeverity, SeverityNullSeverity:
		return nil
	default:
		return fmt.Errorf("finding: invalid enum value for severity field: %q", s)
	}
}

// Difficulty defines the type for the "difficulty" enum field.
type Difficulty string

// Difficulty values.
const (
	DifficultyZeroDifficulty     Difficulty = "ZeroDifficulty"
	DifficultyNoviceDifficulty   Difficulty = "NoviceDifficulty"
	DifficultyAdvancedDifficulty Difficulty = "AdvancedDifficulty"
	DifficultyExpertDifficulty   Difficulty = "ExpertDifficulty"
	DifficultyNullDifficulty     Difficulty = "NullDifficulty"
)

func (d Difficulty) String() string {
	return string(d)
}

// DifficultyValidator is a validator for the "difficulty" field enum values. It is called by the builders before save.
func DifficultyValidator(d Difficulty) error {
	switch d {
	case DifficultyZeroDifficulty, DifficultyNoviceDifficulty, DifficultyAdvancedDifficulty, DifficultyExpertDifficulty, DifficultyNullDifficulty:
		return nil
	default:
		return fmt.Errorf("finding: invalid enum value for difficulty field: %q", d)
	}
}

// MarshalGQL implements graphql.Marshaler interface.
func (s Severity) MarshalGQL(w io.Writer) {
	io.WriteString(w, strconv.Quote(s.String()))
}

// UnmarshalGQL implements graphql.Unmarshaler interface.
func (s *Severity) UnmarshalGQL(val interface{}) error {
	str, ok := val.(string)
	if !ok {
		return fmt.Errorf("enum %T must be a string", val)
	}
	*s = Severity(str)
	if err := SeverityValidator(*s); err != nil {
		return fmt.Errorf("%s is not a valid Severity", str)
	}
	return nil
}

// MarshalGQL implements graphql.Marshaler interface.
func (d Difficulty) MarshalGQL(w io.Writer) {
	io.WriteString(w, strconv.Quote(d.String()))
}

// UnmarshalGQL implements graphql.Unmarshaler interface.
func (d *Difficulty) UnmarshalGQL(val interface{}) error {
	str, ok := val.(string)
	if !ok {
		return fmt.Errorf("enum %T must be a string", val)
	}
	*d = Difficulty(str)
	if err := DifficultyValidator(*d); err != nil {
		return fmt.Errorf("%s is not a valid Difficulty", str)
	}
	return nil
}
