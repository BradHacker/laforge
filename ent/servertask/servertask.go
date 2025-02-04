// Code generated by ent, DO NOT EDIT.

package servertask

import (
	"fmt"
	"io"
	"strconv"

	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the servertask type in the database.
	Label = "server_task"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldType holds the string denoting the type field in the database.
	FieldType = "type"
	// FieldStartTime holds the string denoting the start_time field in the database.
	FieldStartTime = "start_time"
	// FieldEndTime holds the string denoting the end_time field in the database.
	FieldEndTime = "end_time"
	// FieldErrors holds the string denoting the errors field in the database.
	FieldErrors = "errors"
	// FieldLogFilePath holds the string denoting the log_file_path field in the database.
	FieldLogFilePath = "log_file_path"
	// EdgeAuthUser holds the string denoting the authuser edge name in mutations.
	EdgeAuthUser = "AuthUser"
	// EdgeStatus holds the string denoting the status edge name in mutations.
	EdgeStatus = "Status"
	// EdgeEnvironment holds the string denoting the environment edge name in mutations.
	EdgeEnvironment = "Environment"
	// EdgeBuild holds the string denoting the build edge name in mutations.
	EdgeBuild = "Build"
	// EdgeBuildCommit holds the string denoting the buildcommit edge name in mutations.
	EdgeBuildCommit = "BuildCommit"
	// EdgeGinFileMiddleware holds the string denoting the ginfilemiddleware edge name in mutations.
	EdgeGinFileMiddleware = "GinFileMiddleware"
	// Table holds the table name of the servertask in the database.
	Table = "server_tasks"
	// AuthUserTable is the table that holds the AuthUser relation/edge.
	AuthUserTable = "server_tasks"
	// AuthUserInverseTable is the table name for the AuthUser entity.
	// It exists in this package in order to avoid circular dependency with the "authuser" package.
	AuthUserInverseTable = "auth_users"
	// AuthUserColumn is the table column denoting the AuthUser relation/edge.
	AuthUserColumn = "server_task_auth_user"
	// StatusTable is the table that holds the Status relation/edge.
	StatusTable = "status"
	// StatusInverseTable is the table name for the Status entity.
	// It exists in this package in order to avoid circular dependency with the "status" package.
	StatusInverseTable = "status"
	// StatusColumn is the table column denoting the Status relation/edge.
	StatusColumn = "server_task_status"
	// EnvironmentTable is the table that holds the Environment relation/edge.
	EnvironmentTable = "server_tasks"
	// EnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	EnvironmentInverseTable = "environments"
	// EnvironmentColumn is the table column denoting the Environment relation/edge.
	EnvironmentColumn = "server_task_environment"
	// BuildTable is the table that holds the Build relation/edge.
	BuildTable = "server_tasks"
	// BuildInverseTable is the table name for the Build entity.
	// It exists in this package in order to avoid circular dependency with the "build" package.
	BuildInverseTable = "builds"
	// BuildColumn is the table column denoting the Build relation/edge.
	BuildColumn = "server_task_build"
	// BuildCommitTable is the table that holds the BuildCommit relation/edge.
	BuildCommitTable = "server_tasks"
	// BuildCommitInverseTable is the table name for the BuildCommit entity.
	// It exists in this package in order to avoid circular dependency with the "buildcommit" package.
	BuildCommitInverseTable = "build_commits"
	// BuildCommitColumn is the table column denoting the BuildCommit relation/edge.
	BuildCommitColumn = "server_task_build_commit"
	// GinFileMiddlewareTable is the table that holds the GinFileMiddleware relation/edge.
	GinFileMiddlewareTable = "gin_file_middlewares"
	// GinFileMiddlewareInverseTable is the table name for the GinFileMiddleware entity.
	// It exists in this package in order to avoid circular dependency with the "ginfilemiddleware" package.
	GinFileMiddlewareInverseTable = "gin_file_middlewares"
	// GinFileMiddlewareColumn is the table column denoting the GinFileMiddleware relation/edge.
	GinFileMiddlewareColumn = "server_task_gin_file_middleware"
)

// Columns holds all SQL columns for servertask fields.
var Columns = []string{
	FieldID,
	FieldType,
	FieldStartTime,
	FieldEndTime,
	FieldErrors,
	FieldLogFilePath,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "server_tasks"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"server_task_auth_user",
	"server_task_environment",
	"server_task_build",
	"server_task_build_commit",
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

// Type defines the type for the "type" enum field.
type Type string

// Type values.
const (
	TypeLOADENV      Type = "LOADENV"
	TypeCREATEBUILD  Type = "CREATEBUILD"
	TypeRENDERFILES  Type = "RENDERFILES"
	TypeDELETEBUILD  Type = "DELETEBUILD"
	TypeREBUILD      Type = "REBUILD"
	TypeEXECUTEBUILD Type = "EXECUTEBUILD"
)

func (_type Type) String() string {
	return string(_type)
}

// TypeValidator is a validator for the "type" field enum values. It is called by the builders before save.
func TypeValidator(_type Type) error {
	switch _type {
	case TypeLOADENV, TypeCREATEBUILD, TypeRENDERFILES, TypeDELETEBUILD, TypeREBUILD, TypeEXECUTEBUILD:
		return nil
	default:
		return fmt.Errorf("servertask: invalid enum value for type field: %q", _type)
	}
}

// MarshalGQL implements graphql.Marshaler interface.
func (_type Type) MarshalGQL(w io.Writer) {
	io.WriteString(w, strconv.Quote(_type.String()))
}

// UnmarshalGQL implements graphql.Unmarshaler interface.
func (_type *Type) UnmarshalGQL(val interface{}) error {
	str, ok := val.(string)
	if !ok {
		return fmt.Errorf("enum %T must be a string", val)
	}
	*_type = Type(str)
	if err := TypeValidator(*_type); err != nil {
		return fmt.Errorf("%s is not a valid Type", str)
	}
	return nil
}
