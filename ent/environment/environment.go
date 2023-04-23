// Code generated by ent, DO NOT EDIT.

package environment

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the environment type in the database.
	Label = "environment"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHclID holds the string denoting the hcl_id field in the database.
	FieldHclID = "hcl_id"
	// FieldCompetitionID holds the string denoting the competition_id field in the database.
	FieldCompetitionID = "competition_id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldBuilder holds the string denoting the builder field in the database.
	FieldBuilder = "builder"
	// FieldTeamCount holds the string denoting the team_count field in the database.
	FieldTeamCount = "team_count"
	// FieldRevision holds the string denoting the revision field in the database.
	FieldRevision = "revision"
	// FieldAdminCidrs holds the string denoting the admin_cidrs field in the database.
	FieldAdminCidrs = "admin_cidrs"
	// FieldExposedVdiPorts holds the string denoting the exposed_vdi_ports field in the database.
	FieldExposedVdiPorts = "exposed_vdi_ports"
	// FieldConfig holds the string denoting the config field in the database.
	FieldConfig = "config"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// EdgeEnvironmentToUser holds the string denoting the environmenttouser edge name in mutations.
	EdgeEnvironmentToUser = "EnvironmentToUser"
	// EdgeEnvironmentToHost holds the string denoting the environmenttohost edge name in mutations.
	EdgeEnvironmentToHost = "EnvironmentToHost"
	// EdgeEnvironmentToCompetition holds the string denoting the environmenttocompetition edge name in mutations.
	EdgeEnvironmentToCompetition = "EnvironmentToCompetition"
	// EdgeEnvironmentToIdentity holds the string denoting the environmenttoidentity edge name in mutations.
	EdgeEnvironmentToIdentity = "EnvironmentToIdentity"
	// EdgeEnvironmentToCommand holds the string denoting the environmenttocommand edge name in mutations.
	EdgeEnvironmentToCommand = "EnvironmentToCommand"
	// EdgeEnvironmentToScript holds the string denoting the environmenttoscript edge name in mutations.
	EdgeEnvironmentToScript = "EnvironmentToScript"
	// EdgeEnvironmentToFileDownload holds the string denoting the environmenttofiledownload edge name in mutations.
	EdgeEnvironmentToFileDownload = "EnvironmentToFileDownload"
	// EdgeEnvironmentToFileDelete holds the string denoting the environmenttofiledelete edge name in mutations.
	EdgeEnvironmentToFileDelete = "EnvironmentToFileDelete"
	// EdgeEnvironmentToFileExtract holds the string denoting the environmenttofileextract edge name in mutations.
	EdgeEnvironmentToFileExtract = "EnvironmentToFileExtract"
	// EdgeEnvironmentToIncludedNetwork holds the string denoting the environmenttoincludednetwork edge name in mutations.
	EdgeEnvironmentToIncludedNetwork = "EnvironmentToIncludedNetwork"
	// EdgeEnvironmentToFinding holds the string denoting the environmenttofinding edge name in mutations.
	EdgeEnvironmentToFinding = "EnvironmentToFinding"
	// EdgeEnvironmentToDNSRecord holds the string denoting the environmenttodnsrecord edge name in mutations.
	EdgeEnvironmentToDNSRecord = "EnvironmentToDNSRecord"
	// EdgeEnvironmentToDNS holds the string denoting the environmenttodns edge name in mutations.
	EdgeEnvironmentToDNS = "EnvironmentToDNS"
	// EdgeEnvironmentToNetwork holds the string denoting the environmenttonetwork edge name in mutations.
	EdgeEnvironmentToNetwork = "EnvironmentToNetwork"
	// EdgeEnvironmentToHostDependency holds the string denoting the environmenttohostdependency edge name in mutations.
	EdgeEnvironmentToHostDependency = "EnvironmentToHostDependency"
	// EdgeEnvironmentToAnsible holds the string denoting the environmenttoansible edge name in mutations.
	EdgeEnvironmentToAnsible = "EnvironmentToAnsible"
	// EdgeEnvironmentToScheduledStep holds the string denoting the environmenttoscheduledstep edge name in mutations.
	EdgeEnvironmentToScheduledStep = "EnvironmentToScheduledStep"
	// EdgeEnvironmentToBuild holds the string denoting the environmenttobuild edge name in mutations.
	EdgeEnvironmentToBuild = "EnvironmentToBuild"
	// EdgeEnvironmentToRepository holds the string denoting the environmenttorepository edge name in mutations.
	EdgeEnvironmentToRepository = "EnvironmentToRepository"
	// EdgeEnvironmentToServerTask holds the string denoting the environmenttoservertask edge name in mutations.
	EdgeEnvironmentToServerTask = "EnvironmentToServerTask"
	// Table holds the table name of the environment in the database.
	Table = "environments"
	// EnvironmentToUserTable is the table that holds the EnvironmentToUser relation/edge. The primary key declared below.
	EnvironmentToUserTable = "environment_EnvironmentToUser"
	// EnvironmentToUserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	EnvironmentToUserInverseTable = "users"
	// EnvironmentToHostTable is the table that holds the EnvironmentToHost relation/edge.
	EnvironmentToHostTable = "hosts"
	// EnvironmentToHostInverseTable is the table name for the Host entity.
	// It exists in this package in order to avoid circular dependency with the "host" package.
	EnvironmentToHostInverseTable = "hosts"
	// EnvironmentToHostColumn is the table column denoting the EnvironmentToHost relation/edge.
	EnvironmentToHostColumn = "environment_environment_to_host"
	// EnvironmentToCompetitionTable is the table that holds the EnvironmentToCompetition relation/edge.
	EnvironmentToCompetitionTable = "competitions"
	// EnvironmentToCompetitionInverseTable is the table name for the Competition entity.
	// It exists in this package in order to avoid circular dependency with the "competition" package.
	EnvironmentToCompetitionInverseTable = "competitions"
	// EnvironmentToCompetitionColumn is the table column denoting the EnvironmentToCompetition relation/edge.
	EnvironmentToCompetitionColumn = "environment_environment_to_competition"
	// EnvironmentToIdentityTable is the table that holds the EnvironmentToIdentity relation/edge.
	EnvironmentToIdentityTable = "identities"
	// EnvironmentToIdentityInverseTable is the table name for the Identity entity.
	// It exists in this package in order to avoid circular dependency with the "identity" package.
	EnvironmentToIdentityInverseTable = "identities"
	// EnvironmentToIdentityColumn is the table column denoting the EnvironmentToIdentity relation/edge.
	EnvironmentToIdentityColumn = "environment_environment_to_identity"
	// EnvironmentToCommandTable is the table that holds the EnvironmentToCommand relation/edge.
	EnvironmentToCommandTable = "commands"
	// EnvironmentToCommandInverseTable is the table name for the Command entity.
	// It exists in this package in order to avoid circular dependency with the "command" package.
	EnvironmentToCommandInverseTable = "commands"
	// EnvironmentToCommandColumn is the table column denoting the EnvironmentToCommand relation/edge.
	EnvironmentToCommandColumn = "environment_environment_to_command"
	// EnvironmentToScriptTable is the table that holds the EnvironmentToScript relation/edge.
	EnvironmentToScriptTable = "scripts"
	// EnvironmentToScriptInverseTable is the table name for the Script entity.
	// It exists in this package in order to avoid circular dependency with the "script" package.
	EnvironmentToScriptInverseTable = "scripts"
	// EnvironmentToScriptColumn is the table column denoting the EnvironmentToScript relation/edge.
	EnvironmentToScriptColumn = "environment_environment_to_script"
	// EnvironmentToFileDownloadTable is the table that holds the EnvironmentToFileDownload relation/edge.
	EnvironmentToFileDownloadTable = "file_downloads"
	// EnvironmentToFileDownloadInverseTable is the table name for the FileDownload entity.
	// It exists in this package in order to avoid circular dependency with the "filedownload" package.
	EnvironmentToFileDownloadInverseTable = "file_downloads"
	// EnvironmentToFileDownloadColumn is the table column denoting the EnvironmentToFileDownload relation/edge.
	EnvironmentToFileDownloadColumn = "environment_environment_to_file_download"
	// EnvironmentToFileDeleteTable is the table that holds the EnvironmentToFileDelete relation/edge.
	EnvironmentToFileDeleteTable = "file_deletes"
	// EnvironmentToFileDeleteInverseTable is the table name for the FileDelete entity.
	// It exists in this package in order to avoid circular dependency with the "filedelete" package.
	EnvironmentToFileDeleteInverseTable = "file_deletes"
	// EnvironmentToFileDeleteColumn is the table column denoting the EnvironmentToFileDelete relation/edge.
	EnvironmentToFileDeleteColumn = "environment_environment_to_file_delete"
	// EnvironmentToFileExtractTable is the table that holds the EnvironmentToFileExtract relation/edge.
	EnvironmentToFileExtractTable = "file_extracts"
	// EnvironmentToFileExtractInverseTable is the table name for the FileExtract entity.
	// It exists in this package in order to avoid circular dependency with the "fileextract" package.
	EnvironmentToFileExtractInverseTable = "file_extracts"
	// EnvironmentToFileExtractColumn is the table column denoting the EnvironmentToFileExtract relation/edge.
	EnvironmentToFileExtractColumn = "environment_environment_to_file_extract"
	// EnvironmentToIncludedNetworkTable is the table that holds the EnvironmentToIncludedNetwork relation/edge. The primary key declared below.
	EnvironmentToIncludedNetworkTable = "environment_EnvironmentToIncludedNetwork"
	// EnvironmentToIncludedNetworkInverseTable is the table name for the IncludedNetwork entity.
	// It exists in this package in order to avoid circular dependency with the "includednetwork" package.
	EnvironmentToIncludedNetworkInverseTable = "included_networks"
	// EnvironmentToFindingTable is the table that holds the EnvironmentToFinding relation/edge.
	EnvironmentToFindingTable = "findings"
	// EnvironmentToFindingInverseTable is the table name for the Finding entity.
	// It exists in this package in order to avoid circular dependency with the "finding" package.
	EnvironmentToFindingInverseTable = "findings"
	// EnvironmentToFindingColumn is the table column denoting the EnvironmentToFinding relation/edge.
	EnvironmentToFindingColumn = "environment_environment_to_finding"
	// EnvironmentToDNSRecordTable is the table that holds the EnvironmentToDNSRecord relation/edge.
	EnvironmentToDNSRecordTable = "dns_records"
	// EnvironmentToDNSRecordInverseTable is the table name for the DNSRecord entity.
	// It exists in this package in order to avoid circular dependency with the "dnsrecord" package.
	EnvironmentToDNSRecordInverseTable = "dns_records"
	// EnvironmentToDNSRecordColumn is the table column denoting the EnvironmentToDNSRecord relation/edge.
	EnvironmentToDNSRecordColumn = "environment_environment_to_dns_record"
	// EnvironmentToDNSTable is the table that holds the EnvironmentToDNS relation/edge. The primary key declared below.
	EnvironmentToDNSTable = "environment_EnvironmentToDNS"
	// EnvironmentToDNSInverseTable is the table name for the DNS entity.
	// It exists in this package in order to avoid circular dependency with the "dns" package.
	EnvironmentToDNSInverseTable = "dn_ss"
	// EnvironmentToNetworkTable is the table that holds the EnvironmentToNetwork relation/edge.
	EnvironmentToNetworkTable = "networks"
	// EnvironmentToNetworkInverseTable is the table name for the Network entity.
	// It exists in this package in order to avoid circular dependency with the "network" package.
	EnvironmentToNetworkInverseTable = "networks"
	// EnvironmentToNetworkColumn is the table column denoting the EnvironmentToNetwork relation/edge.
	EnvironmentToNetworkColumn = "environment_environment_to_network"
	// EnvironmentToHostDependencyTable is the table that holds the EnvironmentToHostDependency relation/edge.
	EnvironmentToHostDependencyTable = "host_dependencies"
	// EnvironmentToHostDependencyInverseTable is the table name for the HostDependency entity.
	// It exists in this package in order to avoid circular dependency with the "hostdependency" package.
	EnvironmentToHostDependencyInverseTable = "host_dependencies"
	// EnvironmentToHostDependencyColumn is the table column denoting the EnvironmentToHostDependency relation/edge.
	EnvironmentToHostDependencyColumn = "environment_environment_to_host_dependency"
	// EnvironmentToAnsibleTable is the table that holds the EnvironmentToAnsible relation/edge.
	EnvironmentToAnsibleTable = "ansibles"
	// EnvironmentToAnsibleInverseTable is the table name for the Ansible entity.
	// It exists in this package in order to avoid circular dependency with the "ansible" package.
	EnvironmentToAnsibleInverseTable = "ansibles"
	// EnvironmentToAnsibleColumn is the table column denoting the EnvironmentToAnsible relation/edge.
	EnvironmentToAnsibleColumn = "environment_environment_to_ansible"
	// EnvironmentToScheduledStepTable is the table that holds the EnvironmentToScheduledStep relation/edge.
	EnvironmentToScheduledStepTable = "scheduled_steps"
	// EnvironmentToScheduledStepInverseTable is the table name for the ScheduledStep entity.
	// It exists in this package in order to avoid circular dependency with the "scheduledstep" package.
	EnvironmentToScheduledStepInverseTable = "scheduled_steps"
	// EnvironmentToScheduledStepColumn is the table column denoting the EnvironmentToScheduledStep relation/edge.
	EnvironmentToScheduledStepColumn = "environment_environment_to_scheduled_step"
	// EnvironmentToBuildTable is the table that holds the EnvironmentToBuild relation/edge.
	EnvironmentToBuildTable = "builds"
	// EnvironmentToBuildInverseTable is the table name for the Build entity.
	// It exists in this package in order to avoid circular dependency with the "build" package.
	EnvironmentToBuildInverseTable = "builds"
	// EnvironmentToBuildColumn is the table column denoting the EnvironmentToBuild relation/edge.
	EnvironmentToBuildColumn = "build_environment"
	// EnvironmentToRepositoryTable is the table that holds the EnvironmentToRepository relation/edge. The primary key declared below.
	EnvironmentToRepositoryTable = "repository_RepositoryToEnvironment"
	// EnvironmentToRepositoryInverseTable is the table name for the Repository entity.
	// It exists in this package in order to avoid circular dependency with the "repository" package.
	EnvironmentToRepositoryInverseTable = "repositories"
	// EnvironmentToServerTaskTable is the table that holds the EnvironmentToServerTask relation/edge.
	EnvironmentToServerTaskTable = "server_tasks"
	// EnvironmentToServerTaskInverseTable is the table name for the ServerTask entity.
	// It exists in this package in order to avoid circular dependency with the "servertask" package.
	EnvironmentToServerTaskInverseTable = "server_tasks"
	// EnvironmentToServerTaskColumn is the table column denoting the EnvironmentToServerTask relation/edge.
	EnvironmentToServerTaskColumn = "server_task_server_task_to_environment"
)

// Columns holds all SQL columns for environment fields.
var Columns = []string{
	FieldID,
	FieldHclID,
	FieldCompetitionID,
	FieldName,
	FieldDescription,
	FieldBuilder,
	FieldTeamCount,
	FieldRevision,
	FieldAdminCidrs,
	FieldExposedVdiPorts,
	FieldConfig,
	FieldTags,
}

var (
	// EnvironmentToUserPrimaryKey and EnvironmentToUserColumn2 are the table columns denoting the
	// primary key for the EnvironmentToUser relation (M2M).
	EnvironmentToUserPrimaryKey = []string{"environment_id", "user_id"}
	// EnvironmentToIncludedNetworkPrimaryKey and EnvironmentToIncludedNetworkColumn2 are the table columns denoting the
	// primary key for the EnvironmentToIncludedNetwork relation (M2M).
	EnvironmentToIncludedNetworkPrimaryKey = []string{"environment_id", "included_network_id"}
	// EnvironmentToDNSPrimaryKey and EnvironmentToDNSColumn2 are the table columns denoting the
	// primary key for the EnvironmentToDNS relation (M2M).
	EnvironmentToDNSPrimaryKey = []string{"environment_id", "dns_id"}
	// EnvironmentToRepositoryPrimaryKey and EnvironmentToRepositoryColumn2 are the table columns denoting the
	// primary key for the EnvironmentToRepository relation (M2M).
	EnvironmentToRepositoryPrimaryKey = []string{"repository_id", "environment_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)
