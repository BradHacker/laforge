// Code generated by entc, DO NOT EDIT.

package command

const (
	// Label holds the string label denoting the command type in the database.
	Label = "command"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldName holds the string denoting the name field in the database.
	FieldName = "name"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldProgram holds the string denoting the program field in the database.
	FieldProgram = "program"
	// FieldArgs holds the string denoting the args field in the database.
	FieldArgs = "args"
	// FieldIgnoreErrors holds the string denoting the ignore_errors field in the database.
	FieldIgnoreErrors = "ignore_errors"
	// FieldDisabled holds the string denoting the disabled field in the database.
	FieldDisabled = "disabled"
	// FieldCooldown holds the string denoting the cooldown field in the database.
	FieldCooldown = "cooldown"
	// FieldTimeout holds the string denoting the timeout field in the database.
	FieldTimeout = "timeout"
	// FieldVars holds the string denoting the vars field in the database.
	FieldVars = "vars"

	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// EdgeTag holds the string denoting the tag edge name in mutations.
	EdgeTag = "tag"

	// Table holds the table name of the command in the database.
	Table = "commands"
	// UserTable is the table the holds the user relation/edge.
	UserTable = "users"
	// UserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UserInverseTable = "users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "command_user"
	// TagTable is the table the holds the tag relation/edge.
	TagTable = "tags"
	// TagInverseTable is the table name for the Tag entity.
	// It exists in this package in order to avoid circular dependency with the "tag" package.
	TagInverseTable = "tags"
	// TagColumn is the table column denoting the tag relation/edge.
	TagColumn = "command_tag"
)

// Columns holds all SQL columns for command fields.
var Columns = []string{
	FieldID,
	FieldName,
	FieldDescription,
	FieldProgram,
	FieldArgs,
	FieldIgnoreErrors,
	FieldDisabled,
	FieldCooldown,
	FieldTimeout,
	FieldVars,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the Command type.
var ForeignKeys = []string{
	"provisioning_step_command",
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
	// CooldownValidator is a validator for the "cooldown" field. It is called by the builders before save.
	CooldownValidator func(int) error
	// TimeoutValidator is a validator for the "timeout" field. It is called by the builders before save.
	TimeoutValidator func(int) error
)
