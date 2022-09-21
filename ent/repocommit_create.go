// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/repocommit"
	"github.com/gen0cide/laforge/ent/repository"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/uuid"
)

// RepoCommitCreate is the builder for creating a RepoCommit entity.
type RepoCommitCreate struct {
	config
	mutation *RepoCommitMutation
	hooks    []Hook
}

// SetRevision sets the "revision" field.
func (rcc *RepoCommitCreate) SetRevision(i int) *RepoCommitCreate {
	rcc.mutation.SetRevision(i)
	return rcc
}

// SetHash sets the "hash" field.
func (rcc *RepoCommitCreate) SetHash(s string) *RepoCommitCreate {
	rcc.mutation.SetHash(s)
	return rcc
}

// SetAuthor sets the "author" field.
func (rcc *RepoCommitCreate) SetAuthor(o object.Signature) *RepoCommitCreate {
	rcc.mutation.SetAuthor(o)
	return rcc
}

// SetCommitter sets the "committer" field.
func (rcc *RepoCommitCreate) SetCommitter(o object.Signature) *RepoCommitCreate {
	rcc.mutation.SetCommitter(o)
	return rcc
}

// SetPgpSignature sets the "pgp_signature" field.
func (rcc *RepoCommitCreate) SetPgpSignature(s string) *RepoCommitCreate {
	rcc.mutation.SetPgpSignature(s)
	return rcc
}

// SetMessage sets the "message" field.
func (rcc *RepoCommitCreate) SetMessage(s string) *RepoCommitCreate {
	rcc.mutation.SetMessage(s)
	return rcc
}

// SetTreeHash sets the "tree_hash" field.
func (rcc *RepoCommitCreate) SetTreeHash(s string) *RepoCommitCreate {
	rcc.mutation.SetTreeHash(s)
	return rcc
}

// SetParentHashes sets the "parent_hashes" field.
func (rcc *RepoCommitCreate) SetParentHashes(s []string) *RepoCommitCreate {
	rcc.mutation.SetParentHashes(s)
	return rcc
}

// SetID sets the "id" field.
func (rcc *RepoCommitCreate) SetID(u uuid.UUID) *RepoCommitCreate {
	rcc.mutation.SetID(u)
	return rcc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (rcc *RepoCommitCreate) SetNillableID(u *uuid.UUID) *RepoCommitCreate {
	if u != nil {
		rcc.SetID(*u)
	}
	return rcc
}

// SetRepoCommitToRepositoryID sets the "RepoCommitToRepository" edge to the Repository entity by ID.
func (rcc *RepoCommitCreate) SetRepoCommitToRepositoryID(id uuid.UUID) *RepoCommitCreate {
	rcc.mutation.SetRepoCommitToRepositoryID(id)
	return rcc
}

// SetNillableRepoCommitToRepositoryID sets the "RepoCommitToRepository" edge to the Repository entity by ID if the given value is not nil.
func (rcc *RepoCommitCreate) SetNillableRepoCommitToRepositoryID(id *uuid.UUID) *RepoCommitCreate {
	if id != nil {
		rcc = rcc.SetRepoCommitToRepositoryID(*id)
	}
	return rcc
}

// SetRepoCommitToRepository sets the "RepoCommitToRepository" edge to the Repository entity.
func (rcc *RepoCommitCreate) SetRepoCommitToRepository(r *Repository) *RepoCommitCreate {
	return rcc.SetRepoCommitToRepositoryID(r.ID)
}

// Mutation returns the RepoCommitMutation object of the builder.
func (rcc *RepoCommitCreate) Mutation() *RepoCommitMutation {
	return rcc.mutation
}

// Save creates the RepoCommit in the database.
func (rcc *RepoCommitCreate) Save(ctx context.Context) (*RepoCommit, error) {
	var (
		err  error
		node *RepoCommit
	)
	rcc.defaults()
	if len(rcc.hooks) == 0 {
		if err = rcc.check(); err != nil {
			return nil, err
		}
		node, err = rcc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*RepoCommitMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = rcc.check(); err != nil {
				return nil, err
			}
			rcc.mutation = mutation
			if node, err = rcc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(rcc.hooks) - 1; i >= 0; i-- {
			if rcc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = rcc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, rcc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*RepoCommit)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from RepoCommitMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (rcc *RepoCommitCreate) SaveX(ctx context.Context) *RepoCommit {
	v, err := rcc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rcc *RepoCommitCreate) Exec(ctx context.Context) error {
	_, err := rcc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rcc *RepoCommitCreate) ExecX(ctx context.Context) {
	if err := rcc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (rcc *RepoCommitCreate) defaults() {
	if _, ok := rcc.mutation.ID(); !ok {
		v := repocommit.DefaultID()
		rcc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rcc *RepoCommitCreate) check() error {
	if _, ok := rcc.mutation.Revision(); !ok {
		return &ValidationError{Name: "revision", err: errors.New(`ent: missing required field "RepoCommit.revision"`)}
	}
	if _, ok := rcc.mutation.Hash(); !ok {
		return &ValidationError{Name: "hash", err: errors.New(`ent: missing required field "RepoCommit.hash"`)}
	}
	if _, ok := rcc.mutation.Author(); !ok {
		return &ValidationError{Name: "author", err: errors.New(`ent: missing required field "RepoCommit.author"`)}
	}
	if _, ok := rcc.mutation.Committer(); !ok {
		return &ValidationError{Name: "committer", err: errors.New(`ent: missing required field "RepoCommit.committer"`)}
	}
	if _, ok := rcc.mutation.PgpSignature(); !ok {
		return &ValidationError{Name: "pgp_signature", err: errors.New(`ent: missing required field "RepoCommit.pgp_signature"`)}
	}
	if _, ok := rcc.mutation.Message(); !ok {
		return &ValidationError{Name: "message", err: errors.New(`ent: missing required field "RepoCommit.message"`)}
	}
	if _, ok := rcc.mutation.TreeHash(); !ok {
		return &ValidationError{Name: "tree_hash", err: errors.New(`ent: missing required field "RepoCommit.tree_hash"`)}
	}
	if _, ok := rcc.mutation.ParentHashes(); !ok {
		return &ValidationError{Name: "parent_hashes", err: errors.New(`ent: missing required field "RepoCommit.parent_hashes"`)}
	}
	return nil
}

func (rcc *RepoCommitCreate) sqlSave(ctx context.Context) (*RepoCommit, error) {
	_node, _spec := rcc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rcc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	return _node, nil
}

func (rcc *RepoCommitCreate) createSpec() (*RepoCommit, *sqlgraph.CreateSpec) {
	var (
		_node = &RepoCommit{config: rcc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: repocommit.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: repocommit.FieldID,
			},
		}
	)
	if id, ok := rcc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := rcc.mutation.Revision(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: repocommit.FieldRevision,
		})
		_node.Revision = value
	}
	if value, ok := rcc.mutation.Hash(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: repocommit.FieldHash,
		})
		_node.Hash = value
	}
	if value, ok := rcc.mutation.Author(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: repocommit.FieldAuthor,
		})
		_node.Author = value
	}
	if value, ok := rcc.mutation.Committer(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: repocommit.FieldCommitter,
		})
		_node.Committer = value
	}
	if value, ok := rcc.mutation.PgpSignature(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: repocommit.FieldPgpSignature,
		})
		_node.PgpSignature = value
	}
	if value, ok := rcc.mutation.Message(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: repocommit.FieldMessage,
		})
		_node.Message = value
	}
	if value, ok := rcc.mutation.TreeHash(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: repocommit.FieldTreeHash,
		})
		_node.TreeHash = value
	}
	if value, ok := rcc.mutation.ParentHashes(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: repocommit.FieldParentHashes,
		})
		_node.ParentHashes = value
	}
	if nodes := rcc.mutation.RepoCommitToRepositoryIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   repocommit.RepoCommitToRepositoryTable,
			Columns: []string{repocommit.RepoCommitToRepositoryColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: repository.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.repository_repository_to_repo_commit = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// RepoCommitCreateBulk is the builder for creating many RepoCommit entities in bulk.
type RepoCommitCreateBulk struct {
	config
	builders []*RepoCommitCreate
}

// Save creates the RepoCommit entities in the database.
func (rccb *RepoCommitCreateBulk) Save(ctx context.Context) ([]*RepoCommit, error) {
	specs := make([]*sqlgraph.CreateSpec, len(rccb.builders))
	nodes := make([]*RepoCommit, len(rccb.builders))
	mutators := make([]Mutator, len(rccb.builders))
	for i := range rccb.builders {
		func(i int, root context.Context) {
			builder := rccb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*RepoCommitMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, rccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rccb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, rccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rccb *RepoCommitCreateBulk) SaveX(ctx context.Context) []*RepoCommit {
	v, err := rccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rccb *RepoCommitCreateBulk) Exec(ctx context.Context) error {
	_, err := rccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rccb *RepoCommitCreateBulk) ExecX(ctx context.Context) {
	if err := rccb.Exec(ctx); err != nil {
		panic(err)
	}
}
