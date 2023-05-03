// Code generated by ent, DO NOT EDIT.

package competition

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the competition type in the database.
	Label = "competition"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHclID holds the string denoting the hcl_id field in the database.
	FieldHclID = "hcl_id"
	// FieldRootPassword holds the string denoting the root_password field in the database.
	FieldRootPassword = "root_password"
	// FieldStartTime holds the string denoting the start_time field in the database.
	FieldStartTime = "start_time"
	// FieldStopTime holds the string denoting the stop_time field in the database.
	FieldStopTime = "stop_time"
	// FieldConfig holds the string denoting the config field in the database.
	FieldConfig = "config"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// EdgeDNS holds the string denoting the dns edge name in mutations.
	EdgeDNS = "DNS"
	// EdgeEnvironment holds the string denoting the environment edge name in mutations.
	EdgeEnvironment = "Environment"
	// EdgeBuilds holds the string denoting the builds edge name in mutations.
	EdgeBuilds = "Builds"
	// Table holds the table name of the competition in the database.
	Table = "competitions"
	// DNSTable is the table that holds the DNS relation/edge. The primary key declared below.
	DNSTable = "competition_DNS"
	// DNSInverseTable is the table name for the DNS entity.
	// It exists in this package in order to avoid circular dependency with the "dns" package.
	DNSInverseTable = "dn_ss"
	// EnvironmentTable is the table that holds the Environment relation/edge.
	EnvironmentTable = "competitions"
	// EnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	EnvironmentInverseTable = "environments"
	// EnvironmentColumn is the table column denoting the Environment relation/edge.
	EnvironmentColumn = "environment_competitions"
	// BuildsTable is the table that holds the Builds relation/edge.
	BuildsTable = "builds"
	// BuildsInverseTable is the table name for the Build entity.
	// It exists in this package in order to avoid circular dependency with the "build" package.
	BuildsInverseTable = "builds"
	// BuildsColumn is the table column denoting the Builds relation/edge.
	BuildsColumn = "build_competition"
)

// Columns holds all SQL columns for competition fields.
var Columns = []string{
	FieldID,
	FieldHclID,
	FieldRootPassword,
	FieldStartTime,
	FieldStopTime,
	FieldConfig,
	FieldTags,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "competitions"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_competitions",
}

var (
	// DNSPrimaryKey and DNSColumn2 are the table columns denoting the
	// primary key for the DNS relation (M2M).
	DNSPrimaryKey = []string{"competition_id", "dns_id"}
)

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
