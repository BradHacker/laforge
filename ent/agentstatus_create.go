// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/agentstatus"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/google/uuid"
)

// AgentStatusCreate is the builder for creating a AgentStatus entity.
type AgentStatusCreate struct {
	config
	mutation *AgentStatusMutation
	hooks    []Hook
}

// SetClientID sets the "ClientID" field.
func (asc *AgentStatusCreate) SetClientID(s string) *AgentStatusCreate {
	asc.mutation.SetClientID(s)
	return asc
}

// SetHostname sets the "Hostname" field.
func (asc *AgentStatusCreate) SetHostname(s string) *AgentStatusCreate {
	asc.mutation.SetHostname(s)
	return asc
}

// SetUpTime sets the "UpTime" field.
func (asc *AgentStatusCreate) SetUpTime(i int64) *AgentStatusCreate {
	asc.mutation.SetUpTime(i)
	return asc
}

// SetBootTime sets the "BootTime" field.
func (asc *AgentStatusCreate) SetBootTime(i int64) *AgentStatusCreate {
	asc.mutation.SetBootTime(i)
	return asc
}

// SetNumProcs sets the "NumProcs" field.
func (asc *AgentStatusCreate) SetNumProcs(i int64) *AgentStatusCreate {
	asc.mutation.SetNumProcs(i)
	return asc
}

// SetOs sets the "Os" field.
func (asc *AgentStatusCreate) SetOs(s string) *AgentStatusCreate {
	asc.mutation.SetOs(s)
	return asc
}

// SetHostID sets the "HostID" field.
func (asc *AgentStatusCreate) SetHostID(s string) *AgentStatusCreate {
	asc.mutation.SetHostID(s)
	return asc
}

// SetLoad1 sets the "Load1" field.
func (asc *AgentStatusCreate) SetLoad1(f float64) *AgentStatusCreate {
	asc.mutation.SetLoad1(f)
	return asc
}

// SetLoad5 sets the "Load5" field.
func (asc *AgentStatusCreate) SetLoad5(f float64) *AgentStatusCreate {
	asc.mutation.SetLoad5(f)
	return asc
}

// SetLoad15 sets the "Load15" field.
func (asc *AgentStatusCreate) SetLoad15(f float64) *AgentStatusCreate {
	asc.mutation.SetLoad15(f)
	return asc
}

// SetTotalMem sets the "TotalMem" field.
func (asc *AgentStatusCreate) SetTotalMem(i int64) *AgentStatusCreate {
	asc.mutation.SetTotalMem(i)
	return asc
}

// SetFreeMem sets the "FreeMem" field.
func (asc *AgentStatusCreate) SetFreeMem(i int64) *AgentStatusCreate {
	asc.mutation.SetFreeMem(i)
	return asc
}

// SetUsedMem sets the "UsedMem" field.
func (asc *AgentStatusCreate) SetUsedMem(i int64) *AgentStatusCreate {
	asc.mutation.SetUsedMem(i)
	return asc
}

// SetTimestamp sets the "Timestamp" field.
func (asc *AgentStatusCreate) SetTimestamp(i int64) *AgentStatusCreate {
	asc.mutation.SetTimestamp(i)
	return asc
}

// SetID sets the "id" field.
func (asc *AgentStatusCreate) SetID(u uuid.UUID) *AgentStatusCreate {
	asc.mutation.SetID(u)
	return asc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (asc *AgentStatusCreate) SetNillableID(u *uuid.UUID) *AgentStatusCreate {
	if u != nil {
		asc.SetID(*u)
	}
	return asc
}

// SetProvisionedHostID sets the "ProvisionedHost" edge to the ProvisionedHost entity by ID.
func (asc *AgentStatusCreate) SetProvisionedHostID(id uuid.UUID) *AgentStatusCreate {
	asc.mutation.SetProvisionedHostID(id)
	return asc
}

// SetNillableProvisionedHostID sets the "ProvisionedHost" edge to the ProvisionedHost entity by ID if the given value is not nil.
func (asc *AgentStatusCreate) SetNillableProvisionedHostID(id *uuid.UUID) *AgentStatusCreate {
	if id != nil {
		asc = asc.SetProvisionedHostID(*id)
	}
	return asc
}

// SetProvisionedHost sets the "ProvisionedHost" edge to the ProvisionedHost entity.
func (asc *AgentStatusCreate) SetProvisionedHost(p *ProvisionedHost) *AgentStatusCreate {
	return asc.SetProvisionedHostID(p.ID)
}

// SetProvisionedNetworkID sets the "ProvisionedNetwork" edge to the ProvisionedNetwork entity by ID.
func (asc *AgentStatusCreate) SetProvisionedNetworkID(id uuid.UUID) *AgentStatusCreate {
	asc.mutation.SetProvisionedNetworkID(id)
	return asc
}

// SetNillableProvisionedNetworkID sets the "ProvisionedNetwork" edge to the ProvisionedNetwork entity by ID if the given value is not nil.
func (asc *AgentStatusCreate) SetNillableProvisionedNetworkID(id *uuid.UUID) *AgentStatusCreate {
	if id != nil {
		asc = asc.SetProvisionedNetworkID(*id)
	}
	return asc
}

// SetProvisionedNetwork sets the "ProvisionedNetwork" edge to the ProvisionedNetwork entity.
func (asc *AgentStatusCreate) SetProvisionedNetwork(p *ProvisionedNetwork) *AgentStatusCreate {
	return asc.SetProvisionedNetworkID(p.ID)
}

// SetBuildID sets the "Build" edge to the Build entity by ID.
func (asc *AgentStatusCreate) SetBuildID(id uuid.UUID) *AgentStatusCreate {
	asc.mutation.SetBuildID(id)
	return asc
}

// SetNillableBuildID sets the "Build" edge to the Build entity by ID if the given value is not nil.
func (asc *AgentStatusCreate) SetNillableBuildID(id *uuid.UUID) *AgentStatusCreate {
	if id != nil {
		asc = asc.SetBuildID(*id)
	}
	return asc
}

// SetBuild sets the "Build" edge to the Build entity.
func (asc *AgentStatusCreate) SetBuild(b *Build) *AgentStatusCreate {
	return asc.SetBuildID(b.ID)
}

// Mutation returns the AgentStatusMutation object of the builder.
func (asc *AgentStatusCreate) Mutation() *AgentStatusMutation {
	return asc.mutation
}

// Save creates the AgentStatus in the database.
func (asc *AgentStatusCreate) Save(ctx context.Context) (*AgentStatus, error) {
	var (
		err  error
		node *AgentStatus
	)
	asc.defaults()
	if len(asc.hooks) == 0 {
		if err = asc.check(); err != nil {
			return nil, err
		}
		node, err = asc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AgentStatusMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = asc.check(); err != nil {
				return nil, err
			}
			asc.mutation = mutation
			if node, err = asc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(asc.hooks) - 1; i >= 0; i-- {
			if asc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = asc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, asc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*AgentStatus)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from AgentStatusMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (asc *AgentStatusCreate) SaveX(ctx context.Context) *AgentStatus {
	v, err := asc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (asc *AgentStatusCreate) Exec(ctx context.Context) error {
	_, err := asc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (asc *AgentStatusCreate) ExecX(ctx context.Context) {
	if err := asc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (asc *AgentStatusCreate) defaults() {
	if _, ok := asc.mutation.ID(); !ok {
		v := agentstatus.DefaultID()
		asc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (asc *AgentStatusCreate) check() error {
	if _, ok := asc.mutation.ClientID(); !ok {
		return &ValidationError{Name: "ClientID", err: errors.New(`ent: missing required field "AgentStatus.ClientID"`)}
	}
	if _, ok := asc.mutation.Hostname(); !ok {
		return &ValidationError{Name: "Hostname", err: errors.New(`ent: missing required field "AgentStatus.Hostname"`)}
	}
	if _, ok := asc.mutation.UpTime(); !ok {
		return &ValidationError{Name: "UpTime", err: errors.New(`ent: missing required field "AgentStatus.UpTime"`)}
	}
	if _, ok := asc.mutation.BootTime(); !ok {
		return &ValidationError{Name: "BootTime", err: errors.New(`ent: missing required field "AgentStatus.BootTime"`)}
	}
	if _, ok := asc.mutation.NumProcs(); !ok {
		return &ValidationError{Name: "NumProcs", err: errors.New(`ent: missing required field "AgentStatus.NumProcs"`)}
	}
	if _, ok := asc.mutation.Os(); !ok {
		return &ValidationError{Name: "Os", err: errors.New(`ent: missing required field "AgentStatus.Os"`)}
	}
	if _, ok := asc.mutation.HostID(); !ok {
		return &ValidationError{Name: "HostID", err: errors.New(`ent: missing required field "AgentStatus.HostID"`)}
	}
	if _, ok := asc.mutation.Load1(); !ok {
		return &ValidationError{Name: "Load1", err: errors.New(`ent: missing required field "AgentStatus.Load1"`)}
	}
	if _, ok := asc.mutation.Load5(); !ok {
		return &ValidationError{Name: "Load5", err: errors.New(`ent: missing required field "AgentStatus.Load5"`)}
	}
	if _, ok := asc.mutation.Load15(); !ok {
		return &ValidationError{Name: "Load15", err: errors.New(`ent: missing required field "AgentStatus.Load15"`)}
	}
	if _, ok := asc.mutation.TotalMem(); !ok {
		return &ValidationError{Name: "TotalMem", err: errors.New(`ent: missing required field "AgentStatus.TotalMem"`)}
	}
	if _, ok := asc.mutation.FreeMem(); !ok {
		return &ValidationError{Name: "FreeMem", err: errors.New(`ent: missing required field "AgentStatus.FreeMem"`)}
	}
	if _, ok := asc.mutation.UsedMem(); !ok {
		return &ValidationError{Name: "UsedMem", err: errors.New(`ent: missing required field "AgentStatus.UsedMem"`)}
	}
	if _, ok := asc.mutation.Timestamp(); !ok {
		return &ValidationError{Name: "Timestamp", err: errors.New(`ent: missing required field "AgentStatus.Timestamp"`)}
	}
	return nil
}

func (asc *AgentStatusCreate) sqlSave(ctx context.Context) (*AgentStatus, error) {
	_node, _spec := asc.createSpec()
	if err := sqlgraph.CreateNode(ctx, asc.driver, _spec); err != nil {
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

func (asc *AgentStatusCreate) createSpec() (*AgentStatus, *sqlgraph.CreateSpec) {
	var (
		_node = &AgentStatus{config: asc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: agentstatus.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: agentstatus.FieldID,
			},
		}
	)
	if id, ok := asc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := asc.mutation.ClientID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agentstatus.FieldClientID,
		})
		_node.ClientID = value
	}
	if value, ok := asc.mutation.Hostname(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agentstatus.FieldHostname,
		})
		_node.Hostname = value
	}
	if value, ok := asc.mutation.UpTime(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldUpTime,
		})
		_node.UpTime = value
	}
	if value, ok := asc.mutation.BootTime(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldBootTime,
		})
		_node.BootTime = value
	}
	if value, ok := asc.mutation.NumProcs(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldNumProcs,
		})
		_node.NumProcs = value
	}
	if value, ok := asc.mutation.Os(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agentstatus.FieldOs,
		})
		_node.Os = value
	}
	if value, ok := asc.mutation.HostID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agentstatus.FieldHostID,
		})
		_node.HostID = value
	}
	if value, ok := asc.mutation.Load1(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeFloat64,
			Value:  value,
			Column: agentstatus.FieldLoad1,
		})
		_node.Load1 = value
	}
	if value, ok := asc.mutation.Load5(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeFloat64,
			Value:  value,
			Column: agentstatus.FieldLoad5,
		})
		_node.Load5 = value
	}
	if value, ok := asc.mutation.Load15(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeFloat64,
			Value:  value,
			Column: agentstatus.FieldLoad15,
		})
		_node.Load15 = value
	}
	if value, ok := asc.mutation.TotalMem(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldTotalMem,
		})
		_node.TotalMem = value
	}
	if value, ok := asc.mutation.FreeMem(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldFreeMem,
		})
		_node.FreeMem = value
	}
	if value, ok := asc.mutation.UsedMem(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldUsedMem,
		})
		_node.UsedMem = value
	}
	if value, ok := asc.mutation.Timestamp(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt64,
			Value:  value,
			Column: agentstatus.FieldTimestamp,
		})
		_node.Timestamp = value
	}
	if nodes := asc.mutation.ProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   agentstatus.ProvisionedHostTable,
			Columns: []string{agentstatus.ProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedhost.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := asc.mutation.ProvisionedNetworkIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agentstatus.ProvisionedNetworkTable,
			Columns: []string{agentstatus.ProvisionedNetworkColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_status_provisioned_network = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := asc.mutation.BuildIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agentstatus.BuildTable,
			Columns: []string{agentstatus.BuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: build.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_status_build = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AgentStatusCreateBulk is the builder for creating many AgentStatus entities in bulk.
type AgentStatusCreateBulk struct {
	config
	builders []*AgentStatusCreate
}

// Save creates the AgentStatus entities in the database.
func (ascb *AgentStatusCreateBulk) Save(ctx context.Context) ([]*AgentStatus, error) {
	specs := make([]*sqlgraph.CreateSpec, len(ascb.builders))
	nodes := make([]*AgentStatus, len(ascb.builders))
	mutators := make([]Mutator, len(ascb.builders))
	for i := range ascb.builders {
		func(i int, root context.Context) {
			builder := ascb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AgentStatusMutation)
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
					_, err = mutators[i+1].Mutate(root, ascb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ascb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, ascb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ascb *AgentStatusCreateBulk) SaveX(ctx context.Context) []*AgentStatus {
	v, err := ascb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ascb *AgentStatusCreateBulk) Exec(ctx context.Context) error {
	_, err := ascb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ascb *AgentStatusCreateBulk) ExecX(ctx context.Context) {
	if err := ascb.Exec(ctx); err != nil {
		panic(err)
	}
}
