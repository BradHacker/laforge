// Code generated by ent, DO NOT EDIT.

package provisioningstep

import (
	"fmt"
	"io"
	"strconv"

	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the provisioningstep type in the database.
	Label = "provisioning_step"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldType holds the string denoting the type field in the database.
	FieldType = "type"
	// FieldStepNumber holds the string denoting the step_number field in the database.
	FieldStepNumber = "step_number"
	// EdgeStatus holds the string denoting the status edge name in mutations.
	EdgeStatus = "Status"
	// EdgeProvisionedHost holds the string denoting the provisionedhost edge name in mutations.
	EdgeProvisionedHost = "ProvisionedHost"
	// EdgeScript holds the string denoting the script edge name in mutations.
	EdgeScript = "Script"
	// EdgeCommand holds the string denoting the command edge name in mutations.
	EdgeCommand = "Command"
	// EdgeDNSRecord holds the string denoting the dnsrecord edge name in mutations.
	EdgeDNSRecord = "DNSRecord"
	// EdgeFileDelete holds the string denoting the filedelete edge name in mutations.
	EdgeFileDelete = "FileDelete"
	// EdgeFileDownload holds the string denoting the filedownload edge name in mutations.
	EdgeFileDownload = "FileDownload"
	// EdgeFileExtract holds the string denoting the fileextract edge name in mutations.
	EdgeFileExtract = "FileExtract"
	// EdgeAnsible holds the string denoting the ansible edge name in mutations.
	EdgeAnsible = "Ansible"
	// EdgePlan holds the string denoting the plan edge name in mutations.
	EdgePlan = "Plan"
	// EdgeAgentTasks holds the string denoting the agenttasks edge name in mutations.
	EdgeAgentTasks = "AgentTasks"
	// EdgeGinFileMiddleware holds the string denoting the ginfilemiddleware edge name in mutations.
	EdgeGinFileMiddleware = "GinFileMiddleware"
	// Table holds the table name of the provisioningstep in the database.
	Table = "provisioning_steps"
	// StatusTable is the table that holds the Status relation/edge.
	StatusTable = "status"
	// StatusInverseTable is the table name for the Status entity.
	// It exists in this package in order to avoid circular dependency with the "status" package.
	StatusInverseTable = "status"
	// StatusColumn is the table column denoting the Status relation/edge.
	StatusColumn = "provisioning_step_status"
	// ProvisionedHostTable is the table that holds the ProvisionedHost relation/edge.
	ProvisionedHostTable = "provisioning_steps"
	// ProvisionedHostInverseTable is the table name for the ProvisionedHost entity.
	// It exists in this package in order to avoid circular dependency with the "provisionedhost" package.
	ProvisionedHostInverseTable = "provisioned_hosts"
	// ProvisionedHostColumn is the table column denoting the ProvisionedHost relation/edge.
	ProvisionedHostColumn = "provisioning_step_provisioned_host"
	// ScriptTable is the table that holds the Script relation/edge.
	ScriptTable = "provisioning_steps"
	// ScriptInverseTable is the table name for the Script entity.
	// It exists in this package in order to avoid circular dependency with the "script" package.
	ScriptInverseTable = "scripts"
	// ScriptColumn is the table column denoting the Script relation/edge.
	ScriptColumn = "provisioning_step_script"
	// CommandTable is the table that holds the Command relation/edge.
	CommandTable = "provisioning_steps"
	// CommandInverseTable is the table name for the Command entity.
	// It exists in this package in order to avoid circular dependency with the "command" package.
	CommandInverseTable = "commands"
	// CommandColumn is the table column denoting the Command relation/edge.
	CommandColumn = "provisioning_step_command"
	// DNSRecordTable is the table that holds the DNSRecord relation/edge.
	DNSRecordTable = "provisioning_steps"
	// DNSRecordInverseTable is the table name for the DNSRecord entity.
	// It exists in this package in order to avoid circular dependency with the "dnsrecord" package.
	DNSRecordInverseTable = "dns_records"
	// DNSRecordColumn is the table column denoting the DNSRecord relation/edge.
	DNSRecordColumn = "provisioning_step_dns_record"
	// FileDeleteTable is the table that holds the FileDelete relation/edge.
	FileDeleteTable = "provisioning_steps"
	// FileDeleteInverseTable is the table name for the FileDelete entity.
	// It exists in this package in order to avoid circular dependency with the "filedelete" package.
	FileDeleteInverseTable = "file_deletes"
	// FileDeleteColumn is the table column denoting the FileDelete relation/edge.
	FileDeleteColumn = "provisioning_step_file_delete"
	// FileDownloadTable is the table that holds the FileDownload relation/edge.
	FileDownloadTable = "provisioning_steps"
	// FileDownloadInverseTable is the table name for the FileDownload entity.
	// It exists in this package in order to avoid circular dependency with the "filedownload" package.
	FileDownloadInverseTable = "file_downloads"
	// FileDownloadColumn is the table column denoting the FileDownload relation/edge.
	FileDownloadColumn = "provisioning_step_file_download"
	// FileExtractTable is the table that holds the FileExtract relation/edge.
	FileExtractTable = "provisioning_steps"
	// FileExtractInverseTable is the table name for the FileExtract entity.
	// It exists in this package in order to avoid circular dependency with the "fileextract" package.
	FileExtractInverseTable = "file_extracts"
	// FileExtractColumn is the table column denoting the FileExtract relation/edge.
	FileExtractColumn = "provisioning_step_file_extract"
	// AnsibleTable is the table that holds the Ansible relation/edge.
	AnsibleTable = "provisioning_steps"
	// AnsibleInverseTable is the table name for the Ansible entity.
	// It exists in this package in order to avoid circular dependency with the "ansible" package.
	AnsibleInverseTable = "ansibles"
	// AnsibleColumn is the table column denoting the Ansible relation/edge.
	AnsibleColumn = "provisioning_step_ansible"
	// PlanTable is the table that holds the Plan relation/edge.
	PlanTable = "provisioning_steps"
	// PlanInverseTable is the table name for the Plan entity.
	// It exists in this package in order to avoid circular dependency with the "plan" package.
	PlanInverseTable = "plans"
	// PlanColumn is the table column denoting the Plan relation/edge.
	PlanColumn = "plan_provisioning_step"
	// AgentTasksTable is the table that holds the AgentTasks relation/edge.
	AgentTasksTable = "agent_tasks"
	// AgentTasksInverseTable is the table name for the AgentTask entity.
	// It exists in this package in order to avoid circular dependency with the "agenttask" package.
	AgentTasksInverseTable = "agent_tasks"
	// AgentTasksColumn is the table column denoting the AgentTasks relation/edge.
	AgentTasksColumn = "agent_task_provisioning_step"
	// GinFileMiddlewareTable is the table that holds the GinFileMiddleware relation/edge.
	GinFileMiddlewareTable = "provisioning_steps"
	// GinFileMiddlewareInverseTable is the table name for the GinFileMiddleware entity.
	// It exists in this package in order to avoid circular dependency with the "ginfilemiddleware" package.
	GinFileMiddlewareInverseTable = "gin_file_middlewares"
	// GinFileMiddlewareColumn is the table column denoting the GinFileMiddleware relation/edge.
	GinFileMiddlewareColumn = "gin_file_middleware_provisioning_step"
)

// Columns holds all SQL columns for provisioningstep fields.
var Columns = []string{
	FieldID,
	FieldType,
	FieldStepNumber,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "provisioning_steps"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"gin_file_middleware_provisioning_step",
	"plan_provisioning_step",
	"provisioning_step_provisioned_host",
	"provisioning_step_script",
	"provisioning_step_command",
	"provisioning_step_dns_record",
	"provisioning_step_file_delete",
	"provisioning_step_file_download",
	"provisioning_step_file_extract",
	"provisioning_step_ansible",
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
	TypeScript       Type = "Script"
	TypeCommand      Type = "Command"
	TypeDNSRecord    Type = "DNSRecord"
	TypeFileDelete   Type = "FileDelete"
	TypeFileDownload Type = "FileDownload"
	TypeFileExtract  Type = "FileExtract"
	TypeAnsible      Type = "Ansible"
)

func (_type Type) String() string {
	return string(_type)
}

// TypeValidator is a validator for the "type" field enum values. It is called by the builders before save.
func TypeValidator(_type Type) error {
	switch _type {
	case TypeScript, TypeCommand, TypeDNSRecord, TypeFileDelete, TypeFileDownload, TypeFileExtract, TypeAnsible:
		return nil
	default:
		return fmt.Errorf("provisioningstep: invalid enum value for type field: %q", _type)
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
