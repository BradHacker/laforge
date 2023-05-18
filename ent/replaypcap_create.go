// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/replaypcap"
	"github.com/google/uuid"
)

// ReplayPcapCreate is the builder for creating a ReplayPcap entity.
type ReplayPcapCreate struct {
	config
	mutation *ReplayPcapMutation
	hooks    []Hook
}

// SetHclID sets the "hcl_id" field.
func (rpc *ReplayPcapCreate) SetHclID(s string) *ReplayPcapCreate {
	rpc.mutation.SetHclID(s)
	return rpc
}

// SetSourceType sets the "source_type" field.
func (rpc *ReplayPcapCreate) SetSourceType(s string) *ReplayPcapCreate {
	rpc.mutation.SetSourceType(s)
	return rpc
}

// SetSource sets the "source" field.
func (rpc *ReplayPcapCreate) SetSource(s string) *ReplayPcapCreate {
	rpc.mutation.SetSource(s)
	return rpc
}

// SetTemplate sets the "template" field.
func (rpc *ReplayPcapCreate) SetTemplate(b bool) *ReplayPcapCreate {
	rpc.mutation.SetTemplate(b)
	return rpc
}

// SetDisabled sets the "disabled" field.
func (rpc *ReplayPcapCreate) SetDisabled(b bool) *ReplayPcapCreate {
	rpc.mutation.SetDisabled(b)
	return rpc
}

// SetAbsPath sets the "abs_path" field.
func (rpc *ReplayPcapCreate) SetAbsPath(s string) *ReplayPcapCreate {
	rpc.mutation.SetAbsPath(s)
	return rpc
}

// SetTags sets the "tags" field.
func (rpc *ReplayPcapCreate) SetTags(m map[string]string) *ReplayPcapCreate {
	rpc.mutation.SetTags(m)
	return rpc
}

// SetID sets the "id" field.
func (rpc *ReplayPcapCreate) SetID(u uuid.UUID) *ReplayPcapCreate {
	rpc.mutation.SetID(u)
	return rpc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (rpc *ReplayPcapCreate) SetNillableID(u *uuid.UUID) *ReplayPcapCreate {
	if u != nil {
		rpc.SetID(*u)
	}
	return rpc
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (rpc *ReplayPcapCreate) SetEnvironmentID(id uuid.UUID) *ReplayPcapCreate {
	rpc.mutation.SetEnvironmentID(id)
	return rpc
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (rpc *ReplayPcapCreate) SetNillableEnvironmentID(id *uuid.UUID) *ReplayPcapCreate {
	if id != nil {
		rpc = rpc.SetEnvironmentID(*id)
	}
	return rpc
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (rpc *ReplayPcapCreate) SetEnvironment(e *Environment) *ReplayPcapCreate {
	return rpc.SetEnvironmentID(e.ID)
}

// Mutation returns the ReplayPcapMutation object of the builder.
func (rpc *ReplayPcapCreate) Mutation() *ReplayPcapMutation {
	return rpc.mutation
}

// Save creates the ReplayPcap in the database.
func (rpc *ReplayPcapCreate) Save(ctx context.Context) (*ReplayPcap, error) {
	var (
		err  error
		node *ReplayPcap
	)
	rpc.defaults()
	if len(rpc.hooks) == 0 {
		if err = rpc.check(); err != nil {
			return nil, err
		}
		node, err = rpc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*ReplayPcapMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = rpc.check(); err != nil {
				return nil, err
			}
			rpc.mutation = mutation
			if node, err = rpc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(rpc.hooks) - 1; i >= 0; i-- {
			if rpc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = rpc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, rpc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*ReplayPcap)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from ReplayPcapMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (rpc *ReplayPcapCreate) SaveX(ctx context.Context) *ReplayPcap {
	v, err := rpc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rpc *ReplayPcapCreate) Exec(ctx context.Context) error {
	_, err := rpc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rpc *ReplayPcapCreate) ExecX(ctx context.Context) {
	if err := rpc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (rpc *ReplayPcapCreate) defaults() {
	if _, ok := rpc.mutation.ID(); !ok {
		v := replaypcap.DefaultID()
		rpc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rpc *ReplayPcapCreate) check() error {
	if _, ok := rpc.mutation.HclID(); !ok {
		return &ValidationError{Name: "hcl_id", err: errors.New(`ent: missing required field "ReplayPcap.hcl_id"`)}
	}
	if _, ok := rpc.mutation.SourceType(); !ok {
		return &ValidationError{Name: "source_type", err: errors.New(`ent: missing required field "ReplayPcap.source_type"`)}
	}
	if _, ok := rpc.mutation.Source(); !ok {
		return &ValidationError{Name: "source", err: errors.New(`ent: missing required field "ReplayPcap.source"`)}
	}
	if _, ok := rpc.mutation.Template(); !ok {
		return &ValidationError{Name: "template", err: errors.New(`ent: missing required field "ReplayPcap.template"`)}
	}
	if _, ok := rpc.mutation.Disabled(); !ok {
		return &ValidationError{Name: "disabled", err: errors.New(`ent: missing required field "ReplayPcap.disabled"`)}
	}
	if _, ok := rpc.mutation.AbsPath(); !ok {
		return &ValidationError{Name: "abs_path", err: errors.New(`ent: missing required field "ReplayPcap.abs_path"`)}
	}
	if _, ok := rpc.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New(`ent: missing required field "ReplayPcap.tags"`)}
	}
	return nil
}

func (rpc *ReplayPcapCreate) sqlSave(ctx context.Context) (*ReplayPcap, error) {
	_node, _spec := rpc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rpc.driver, _spec); err != nil {
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

func (rpc *ReplayPcapCreate) createSpec() (*ReplayPcap, *sqlgraph.CreateSpec) {
	var (
		_node = &ReplayPcap{config: rpc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: replaypcap.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: replaypcap.FieldID,
			},
		}
	)
	if id, ok := rpc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := rpc.mutation.HclID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: replaypcap.FieldHclID,
		})
		_node.HclID = value
	}
	if value, ok := rpc.mutation.SourceType(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: replaypcap.FieldSourceType,
		})
		_node.SourceType = value
	}
	if value, ok := rpc.mutation.Source(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: replaypcap.FieldSource,
		})
		_node.Source = value
	}
	if value, ok := rpc.mutation.Template(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: replaypcap.FieldTemplate,
		})
		_node.Template = value
	}
	if value, ok := rpc.mutation.Disabled(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: replaypcap.FieldDisabled,
		})
		_node.Disabled = value
	}
	if value, ok := rpc.mutation.AbsPath(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: replaypcap.FieldAbsPath,
		})
		_node.AbsPath = value
	}
	if value, ok := rpc.mutation.Tags(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: replaypcap.FieldTags,
		})
		_node.Tags = value
	}
	if nodes := rpc.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   replaypcap.EnvironmentTable,
			Columns: []string{replaypcap.EnvironmentColumn},
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
		_node.environment_replay_pcaps = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ReplayPcapCreateBulk is the builder for creating many ReplayPcap entities in bulk.
type ReplayPcapCreateBulk struct {
	config
	builders []*ReplayPcapCreate
}

// Save creates the ReplayPcap entities in the database.
func (rpcb *ReplayPcapCreateBulk) Save(ctx context.Context) ([]*ReplayPcap, error) {
	specs := make([]*sqlgraph.CreateSpec, len(rpcb.builders))
	nodes := make([]*ReplayPcap, len(rpcb.builders))
	mutators := make([]Mutator, len(rpcb.builders))
	for i := range rpcb.builders {
		func(i int, root context.Context) {
			builder := rpcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ReplayPcapMutation)
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
					_, err = mutators[i+1].Mutate(root, rpcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rpcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, rpcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rpcb *ReplayPcapCreateBulk) SaveX(ctx context.Context) []*ReplayPcap {
	v, err := rpcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rpcb *ReplayPcapCreateBulk) Exec(ctx context.Context) error {
	_, err := rpcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rpcb *ReplayPcapCreateBulk) ExecX(ctx context.Context) {
	if err := rpcb.Exec(ctx); err != nil {
		panic(err)
	}
}
