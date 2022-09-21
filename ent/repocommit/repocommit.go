// Code generated by ent, DO NOT EDIT.

package repocommit

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the repocommit type in the database.
	Label = "repo_commit"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldRevision holds the string denoting the revision field in the database.
	FieldRevision = "revision"
	// FieldHash holds the string denoting the hash field in the database.
	FieldHash = "hash"
	// FieldAuthor holds the string denoting the author field in the database.
	FieldAuthor = "author"
	// FieldCommitter holds the string denoting the committer field in the database.
	FieldCommitter = "committer"
	// FieldPgpSignature holds the string denoting the pgp_signature field in the database.
	FieldPgpSignature = "pgp_signature"
	// FieldMessage holds the string denoting the message field in the database.
	FieldMessage = "message"
	// FieldTreeHash holds the string denoting the tree_hash field in the database.
	FieldTreeHash = "tree_hash"
	// FieldParentHashes holds the string denoting the parent_hashes field in the database.
	FieldParentHashes = "parent_hashes"
	// EdgeRepoCommitToRepository holds the string denoting the repocommittorepository edge name in mutations.
	EdgeRepoCommitToRepository = "RepoCommitToRepository"
	// Table holds the table name of the repocommit in the database.
	Table = "repo_commits"
	// RepoCommitToRepositoryTable is the table that holds the RepoCommitToRepository relation/edge.
	RepoCommitToRepositoryTable = "repo_commits"
	// RepoCommitToRepositoryInverseTable is the table name for the Repository entity.
	// It exists in this package in order to avoid circular dependency with the "repository" package.
	RepoCommitToRepositoryInverseTable = "repositories"
	// RepoCommitToRepositoryColumn is the table column denoting the RepoCommitToRepository relation/edge.
	RepoCommitToRepositoryColumn = "repository_repository_to_repo_commit"
)

// Columns holds all SQL columns for repocommit fields.
var Columns = []string{
	FieldID,
	FieldRevision,
	FieldHash,
	FieldAuthor,
	FieldCommitter,
	FieldPgpSignature,
	FieldMessage,
	FieldTreeHash,
	FieldParentHashes,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "repo_commits"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"repository_repository_to_repo_commit",
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
