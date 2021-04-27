// Code generated by entc, DO NOT EDIT.

package identity

const (
	// Label holds the string label denoting the identity type in the database.
	Label = "identity"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldHclID holds the string denoting the hcl_id field in the database.
	FieldHclID = "hcl_id"
	// FieldFirstName holds the string denoting the first_name field in the database.
	FieldFirstName = "first_name"
	// FieldLastName holds the string denoting the last_name field in the database.
	FieldLastName = "last_name"
	// FieldEmail holds the string denoting the email field in the database.
	FieldEmail = "email"
	// FieldPassword holds the string denoting the password field in the database.
	FieldPassword = "password"
	// FieldDescription holds the string denoting the description field in the database.
	FieldDescription = "description"
	// FieldAvatarFile holds the string denoting the avatar_file field in the database.
	FieldAvatarFile = "avatar_file"
	// FieldVars holds the string denoting the vars field in the database.
	FieldVars = "vars"
	// FieldTags holds the string denoting the tags field in the database.
	FieldTags = "tags"
	// EdgeIdentityToEnvironment holds the string denoting the identitytoenvironment edge name in mutations.
	EdgeIdentityToEnvironment = "IdentityToEnvironment"
	// Table holds the table name of the identity in the database.
	Table = "identities"
	// IdentityToEnvironmentTable is the table the holds the IdentityToEnvironment relation/edge.
	IdentityToEnvironmentTable = "identities"
	// IdentityToEnvironmentInverseTable is the table name for the Environment entity.
	// It exists in this package in order to avoid circular dependency with the "environment" package.
	IdentityToEnvironmentInverseTable = "environments"
	// IdentityToEnvironmentColumn is the table column denoting the IdentityToEnvironment relation/edge.
	IdentityToEnvironmentColumn = "environment_environment_to_identity"
)

// Columns holds all SQL columns for identity fields.
var Columns = []string{
	FieldID,
	FieldHclID,
	FieldFirstName,
	FieldLastName,
	FieldEmail,
	FieldPassword,
	FieldDescription,
	FieldAvatarFile,
	FieldVars,
	FieldTags,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "identities"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"environment_environment_to_identity",
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
