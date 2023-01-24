// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/identity"
	"github.com/google/uuid"
)

// IdentityCreate is the builder for creating a Identity entity.
type IdentityCreate struct {
	config
	mutation *IdentityMutation
	hooks    []Hook
}

// SetHclID sets the "hcl_id" field.
func (ic *IdentityCreate) SetHclID(s string) *IdentityCreate {
	ic.mutation.SetHclID(s)
	return ic
}

// SetFirstName sets the "first_name" field.
func (ic *IdentityCreate) SetFirstName(s string) *IdentityCreate {
	ic.mutation.SetFirstName(s)
	return ic
}

// SetLastName sets the "last_name" field.
func (ic *IdentityCreate) SetLastName(s string) *IdentityCreate {
	ic.mutation.SetLastName(s)
	return ic
}

// SetEmail sets the "email" field.
func (ic *IdentityCreate) SetEmail(s string) *IdentityCreate {
	ic.mutation.SetEmail(s)
	return ic
}

// SetPassword sets the "password" field.
func (ic *IdentityCreate) SetPassword(s string) *IdentityCreate {
	ic.mutation.SetPassword(s)
	return ic
}

// SetDescription sets the "description" field.
func (ic *IdentityCreate) SetDescription(s string) *IdentityCreate {
	ic.mutation.SetDescription(s)
	return ic
}

// SetAvatarFile sets the "avatar_file" field.
func (ic *IdentityCreate) SetAvatarFile(s string) *IdentityCreate {
	ic.mutation.SetAvatarFile(s)
	return ic
}

// SetVars sets the "vars" field.
func (ic *IdentityCreate) SetVars(m map[string]string) *IdentityCreate {
	ic.mutation.SetVars(m)
	return ic
}

// SetTags sets the "tags" field.
func (ic *IdentityCreate) SetTags(m map[string]string) *IdentityCreate {
	ic.mutation.SetTags(m)
	return ic
}

// SetID sets the "id" field.
func (ic *IdentityCreate) SetID(u uuid.UUID) *IdentityCreate {
	ic.mutation.SetID(u)
	return ic
}

// SetNillableID sets the "id" field if the given value is not nil.
func (ic *IdentityCreate) SetNillableID(u *uuid.UUID) *IdentityCreate {
	if u != nil {
		ic.SetID(*u)
	}
	return ic
}

// SetIdentityToEnvironmentID sets the "IdentityToEnvironment" edge to the Environment entity by ID.
func (ic *IdentityCreate) SetIdentityToEnvironmentID(id uuid.UUID) *IdentityCreate {
	ic.mutation.SetIdentityToEnvironmentID(id)
	return ic
}

// SetNillableIdentityToEnvironmentID sets the "IdentityToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (ic *IdentityCreate) SetNillableIdentityToEnvironmentID(id *uuid.UUID) *IdentityCreate {
	if id != nil {
		ic = ic.SetIdentityToEnvironmentID(*id)
	}
	return ic
}

// SetIdentityToEnvironment sets the "IdentityToEnvironment" edge to the Environment entity.
func (ic *IdentityCreate) SetIdentityToEnvironment(e *Environment) *IdentityCreate {
	return ic.SetIdentityToEnvironmentID(e.ID)
}

// Mutation returns the IdentityMutation object of the builder.
func (ic *IdentityCreate) Mutation() *IdentityMutation {
	return ic.mutation
}

// Save creates the Identity in the database.
func (ic *IdentityCreate) Save(ctx context.Context) (*Identity, error) {
	var (
		err  error
		node *Identity
	)
	ic.defaults()
	if len(ic.hooks) == 0 {
		if err = ic.check(); err != nil {
			return nil, err
		}
		node, err = ic.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*IdentityMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = ic.check(); err != nil {
				return nil, err
			}
			ic.mutation = mutation
			if node, err = ic.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(ic.hooks) - 1; i >= 0; i-- {
			if ic.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = ic.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, ic.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*Identity)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from IdentityMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (ic *IdentityCreate) SaveX(ctx context.Context) *Identity {
	v, err := ic.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ic *IdentityCreate) Exec(ctx context.Context) error {
	_, err := ic.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ic *IdentityCreate) ExecX(ctx context.Context) {
	if err := ic.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ic *IdentityCreate) defaults() {
	if _, ok := ic.mutation.ID(); !ok {
		v := identity.DefaultID()
		ic.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ic *IdentityCreate) check() error {
	if _, ok := ic.mutation.HclID(); !ok {
		return &ValidationError{Name: "hcl_id", err: errors.New(`ent: missing required field "Identity.hcl_id"`)}
	}
	if _, ok := ic.mutation.FirstName(); !ok {
		return &ValidationError{Name: "first_name", err: errors.New(`ent: missing required field "Identity.first_name"`)}
	}
	if _, ok := ic.mutation.LastName(); !ok {
		return &ValidationError{Name: "last_name", err: errors.New(`ent: missing required field "Identity.last_name"`)}
	}
	if _, ok := ic.mutation.Email(); !ok {
		return &ValidationError{Name: "email", err: errors.New(`ent: missing required field "Identity.email"`)}
	}
	if _, ok := ic.mutation.Password(); !ok {
		return &ValidationError{Name: "password", err: errors.New(`ent: missing required field "Identity.password"`)}
	}
	if _, ok := ic.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "Identity.description"`)}
	}
	if _, ok := ic.mutation.AvatarFile(); !ok {
		return &ValidationError{Name: "avatar_file", err: errors.New(`ent: missing required field "Identity.avatar_file"`)}
	}
	if _, ok := ic.mutation.Vars(); !ok {
		return &ValidationError{Name: "vars", err: errors.New(`ent: missing required field "Identity.vars"`)}
	}
	if _, ok := ic.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New(`ent: missing required field "Identity.tags"`)}
	}
	return nil
}

func (ic *IdentityCreate) sqlSave(ctx context.Context) (*Identity, error) {
	_node, _spec := ic.createSpec()
	if err := sqlgraph.CreateNode(ctx, ic.driver, _spec); err != nil {
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

func (ic *IdentityCreate) createSpec() (*Identity, *sqlgraph.CreateSpec) {
	var (
		_node = &Identity{config: ic.config}
		_spec = &sqlgraph.CreateSpec{
			Table: identity.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: identity.FieldID,
			},
		}
	)
	if id, ok := ic.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := ic.mutation.HclID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldHclID,
		})
		_node.HclID = value
	}
	if value, ok := ic.mutation.FirstName(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldFirstName,
		})
		_node.FirstName = value
	}
	if value, ok := ic.mutation.LastName(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldLastName,
		})
		_node.LastName = value
	}
	if value, ok := ic.mutation.Email(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldEmail,
		})
		_node.Email = value
	}
	if value, ok := ic.mutation.Password(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldPassword,
		})
		_node.Password = value
	}
	if value, ok := ic.mutation.Description(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldDescription,
		})
		_node.Description = value
	}
	if value, ok := ic.mutation.AvatarFile(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: identity.FieldAvatarFile,
		})
		_node.AvatarFile = value
	}
	if value, ok := ic.mutation.Vars(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: identity.FieldVars,
		})
		_node.Vars = value
	}
	if value, ok := ic.mutation.Tags(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: identity.FieldTags,
		})
		_node.Tags = value
	}
	if nodes := ic.mutation.IdentityToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   identity.IdentityToEnvironmentTable,
			Columns: []string{identity.IdentityToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.environment_environment_to_identity = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// IdentityCreateBulk is the builder for creating many Identity entities in bulk.
type IdentityCreateBulk struct {
	config
	builders []*IdentityCreate
}

// Save creates the Identity entities in the database.
func (icb *IdentityCreateBulk) Save(ctx context.Context) ([]*Identity, error) {
	specs := make([]*sqlgraph.CreateSpec, len(icb.builders))
	nodes := make([]*Identity, len(icb.builders))
	mutators := make([]Mutator, len(icb.builders))
	for i := range icb.builders {
		func(i int, root context.Context) {
			builder := icb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*IdentityMutation)
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
					_, err = mutators[i+1].Mutate(root, icb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, icb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, icb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (icb *IdentityCreateBulk) SaveX(ctx context.Context) []*Identity {
	v, err := icb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (icb *IdentityCreateBulk) Exec(ctx context.Context) error {
	_, err := icb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (icb *IdentityCreateBulk) ExecX(ctx context.Context) {
	if err := icb.Exec(ctx); err != nil {
		panic(err)
	}
}
