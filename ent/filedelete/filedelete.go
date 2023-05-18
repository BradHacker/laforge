// Code generated by ent, DO NOT EDIT.

package filedelete

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the filedelete type in the database.
	Label = "file_delete"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHclID holds the string denoting the hcl_id field in the database.
	FieldHclID = "hcl_id"
	// FieldPath holds the string denoting the path field in the database.
	FieldPath = "path"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// FieldValidations holds the string denoting the validations field in the database.
	FieldValidations = "validations"
	// EdgeEnvironment holds the string denoting the environment edge name in mutations.
	EdgeEnvironment = "Environment"
	// Table holds the table name of the filedelete in the database.
	Table = "file_deletes"
	// EnvironmentTable is the table that holds the Environment relation/edge.
	EnvironmentTable = "file_deletes"
	// EnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	EnvironmentInverseTable = "environments"
	// EnvironmentColumn is the table column denoting the Environment relation/edge.
	EnvironmentColumn = "environment_file_deletes"
)

// Columns holds all SQL columns for filedelete fields.
var Columns = []string{
	FieldID,
	FieldHclID,
	FieldPath,
	FieldTags,
	FieldValidations,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "file_deletes"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_file_deletes",
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
