// Code generated by ent, DO NOT EDIT.

package hostdependency

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the hostdependency type in the database.
	Label = "host_dependency"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHostID holds the string denoting the host_id field in the database.
	FieldHostID = "host_id"
	// FieldNetworkID holds the string denoting the network_id field in the database.
	FieldNetworkID = "network_id"
	// EdgeRequiredBy holds the string denoting the requiredby edge name in mutations.
	EdgeRequiredBy = "RequiredBy"
	// EdgeDependOnHost holds the string denoting the dependonhost edge name in mutations.
	EdgeDependOnHost = "DependOnHost"
	// EdgeDependOnNetwork holds the string denoting the dependonnetwork edge name in mutations.
	EdgeDependOnNetwork = "DependOnNetwork"
	// EdgeEnvironment holds the string denoting the environment edge name in mutations.
	EdgeEnvironment = "Environment"
	// Table holds the table name of the hostdependency in the database.
	Table = "host_dependencies"
	// RequiredByTable is the table that holds the RequiredBy relation/edge.
	RequiredByTable = "host_dependencies"
	// RequiredByInverseTable is the table name for the Host entity.
	// It exists in this package in order to avoid circular dependency with the "host" package.
	RequiredByInverseTable = "hosts"
	// RequiredByColumn is the table column denoting the RequiredBy relation/edge.
	RequiredByColumn = "host_dependency_required_by"
	// DependOnHostTable is the table that holds the DependOnHost relation/edge.
	DependOnHostTable = "host_dependencies"
	// DependOnHostInverseTable is the table name for the Host entity.
	// It exists in this package in order to avoid circular dependency with the "host" package.
	DependOnHostInverseTable = "hosts"
	// DependOnHostColumn is the table column denoting the DependOnHost relation/edge.
	DependOnHostColumn = "host_dependency_depend_on_host"
	// DependOnNetworkTable is the table that holds the DependOnNetwork relation/edge.
	DependOnNetworkTable = "host_dependencies"
	// DependOnNetworkInverseTable is the table name for the Network entity.
	// It exists in this package in order to avoid circular dependency with the "network" package.
	DependOnNetworkInverseTable = "networks"
	// DependOnNetworkColumn is the table column denoting the DependOnNetwork relation/edge.
	DependOnNetworkColumn = "host_dependency_depend_on_network"
	// EnvironmentTable is the table that holds the Environment relation/edge.
	EnvironmentTable = "host_dependencies"
	// EnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	EnvironmentInverseTable = "environments"
	// EnvironmentColumn is the table column denoting the Environment relation/edge.
	EnvironmentColumn = "environment_host_dependencies"
)

// Columns holds all SQL columns for hostdependency fields.
var Columns = []string{
	FieldID,
	FieldHostID,
	FieldNetworkID,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "host_dependencies"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_host_dependencies",
	"host_dependency_required_by",
	"host_dependency_depend_on_host",
	"host_dependency_depend_on_network",
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
