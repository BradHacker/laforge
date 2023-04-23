// Code generated by ent, DO NOT EDIT.

package network

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the network type in the database.
	Label = "network"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHclID holds the string denoting the hcl_id field in the database.
	FieldHclID = "hcl_id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldCidr holds the string denoting the cidr field in the database.
	FieldCidr = "cidr"
	// FieldVdiVisible holds the string denoting the vdi_visible field in the database.
	FieldVdiVisible = "vdi_visible"
	// FieldVars holds the string denoting the vars field in the database.
	FieldVars = "vars"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// EdgeNetworkToEnvironment holds the string denoting the networktoenvironment edge name in mutations.
	EdgeNetworkToEnvironment = "NetworkToEnvironment"
	// EdgeNetworkToHostDependency holds the string denoting the networktohostdependency edge name in mutations.
	EdgeNetworkToHostDependency = "NetworkToHostDependency"
	// EdgeNetworkToIncludedNetwork holds the string denoting the networktoincludednetwork edge name in mutations.
	EdgeNetworkToIncludedNetwork = "NetworkToIncludedNetwork"
	// Table holds the table name of the network in the database.
	Table = "networks"
	// NetworkToEnvironmentTable is the table that holds the NetworkToEnvironment relation/edge.
	NetworkToEnvironmentTable = "networks"
	// NetworkToEnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	NetworkToEnvironmentInverseTable = "environments"
	// NetworkToEnvironmentColumn is the table column denoting the NetworkToEnvironment relation/edge.
	NetworkToEnvironmentColumn = "environment_networks"
	// NetworkToHostDependencyTable is the table that holds the NetworkToHostDependency relation/edge.
	NetworkToHostDependencyTable = "host_dependencies"
	// NetworkToHostDependencyInverseTable is the table name for the HostDependency entity.
	// It exists in this package in order to avoid circular dependency with the "hostdependency" package.
	NetworkToHostDependencyInverseTable = "host_dependencies"
	// NetworkToHostDependencyColumn is the table column denoting the NetworkToHostDependency relation/edge.
	NetworkToHostDependencyColumn = "host_dependency_host_dependency_to_network"
	// NetworkToIncludedNetworkTable is the table that holds the NetworkToIncludedNetwork relation/edge.
	NetworkToIncludedNetworkTable = "included_networks"
	// NetworkToIncludedNetworkInverseTable is the table name for the IncludedNetwork entity.
	// It exists in this package in order to avoid circular dependency with the "includednetwork" package.
	NetworkToIncludedNetworkInverseTable = "included_networks"
	// NetworkToIncludedNetworkColumn is the table column denoting the NetworkToIncludedNetwork relation/edge.
	NetworkToIncludedNetworkColumn = "included_network_included_network_to_network"
)

// Columns holds all SQL columns for network fields.
var Columns = []string{
	FieldID,
	FieldHclID,
	FieldName,
	FieldCidr,
	FieldVdiVisible,
	FieldVars,
	FieldTags,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "networks"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_networks",
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
