// Code generated by entc, DO NOT EDIT.

package competition

const (
	// Label holds the string label denoting the competition type in the database.
	Label = "competition"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHclID holds the string denoting the hcl_id field in the database.
	FieldHclID = "hcl_id"
	// FieldRootPassword holds the string denoting the root_password field in the database.
	FieldRootPassword = "root_password"
	// FieldConfig holds the string denoting the config field in the database.
	FieldConfig = "config"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// EdgeCompetitionToDNS holds the string denoting the competitiontodns edge name in mutations.
	EdgeCompetitionToDNS = "CompetitionToDNS"
	// EdgeCompetitionToEnvironment holds the string denoting the competitiontoenvironment edge name in mutations.
	EdgeCompetitionToEnvironment = "CompetitionToEnvironment"
	// EdgeCompetitionToBuild holds the string denoting the competitiontobuild edge name in mutations.
	EdgeCompetitionToBuild = "CompetitionToBuild"
	// Table holds the table name of the competition in the database.
	Table = "competitions"
	// CompetitionToDNSTable is the table the holds the CompetitionToDNS relation/edge. The primary key declared below.
	CompetitionToDNSTable = "competition_CompetitionToDNS"
	// CompetitionToDNSInverseTable is the table name for the DNS entity.
	// It exists in this package in order to avoid circular dependency with the "dns" package.
	CompetitionToDNSInverseTable = "dn_ss"
	// CompetitionToEnvironmentTable is the table the holds the CompetitionToEnvironment relation/edge.
	CompetitionToEnvironmentTable = "competitions"
	// CompetitionToEnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	CompetitionToEnvironmentInverseTable = "environments"
	// CompetitionToEnvironmentColumn is the table column denoting the CompetitionToEnvironment relation/edge.
	CompetitionToEnvironmentColumn = "environment_environment_to_competition"
	// CompetitionToBuildTable is the table the holds the CompetitionToBuild relation/edge.
	CompetitionToBuildTable = "builds"
	// CompetitionToBuildInverseTable is the table name for the Build entity.
	// It exists in this package in order to avoid circular dependency with the "build" package.
	CompetitionToBuildInverseTable = "builds"
	// CompetitionToBuildColumn is the table column denoting the CompetitionToBuild relation/edge.
	CompetitionToBuildColumn = "build_build_to_competition"
)

// Columns holds all SQL columns for competition fields.
var Columns = []string{
	FieldID,
	FieldHclID,
	FieldRootPassword,
	FieldConfig,
	FieldTags,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "competitions"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_environment_to_competition",
}

var (
	// CompetitionToDNSPrimaryKey and CompetitionToDNSColumn2 are the table columns denoting the
	// primary key for the CompetitionToDNS relation (M2M).
	CompetitionToDNSPrimaryKey = []string{"competition_id", "dns_id"}
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
