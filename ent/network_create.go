// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/hostdependency"
	"github.com/gen0cide/laforge/ent/includednetwork"
	"github.com/gen0cide/laforge/ent/network"
	"github.com/google/uuid"
)

// NetworkCreate is the builder for creating a Network entity.
type NetworkCreate struct {
	config
	mutation *NetworkMutation
	hooks    []Hook
}

// SetHCLID sets the "hcl_id" field.
func (nc *NetworkCreate) SetHCLID(s string) *NetworkCreate {
	nc.mutation.SetHCLID(s)
	return nc
}

// SetName sets the "name" field.
func (nc *NetworkCreate) SetName(s string) *NetworkCreate {
	nc.mutation.SetName(s)
	return nc
}

// SetCidr sets the "cidr" field.
func (nc *NetworkCreate) SetCidr(s string) *NetworkCreate {
	nc.mutation.SetCidr(s)
	return nc
}

// SetVdiVisible sets the "vdi_visible" field.
func (nc *NetworkCreate) SetVdiVisible(b bool) *NetworkCreate {
	nc.mutation.SetVdiVisible(b)
	return nc
}

// SetVars sets the "vars" field.
func (nc *NetworkCreate) SetVars(m map[string]string) *NetworkCreate {
	nc.mutation.SetVars(m)
	return nc
}

// SetTags sets the "tags" field.
func (nc *NetworkCreate) SetTags(m map[string]string) *NetworkCreate {
	nc.mutation.SetTags(m)
	return nc
}

// SetID sets the "id" field.
func (nc *NetworkCreate) SetID(u uuid.UUID) *NetworkCreate {
	nc.mutation.SetID(u)
	return nc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (nc *NetworkCreate) SetNillableID(u *uuid.UUID) *NetworkCreate {
	if u != nil {
		nc.SetID(*u)
	}
	return nc
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (nc *NetworkCreate) SetEnvironmentID(id uuid.UUID) *NetworkCreate {
	nc.mutation.SetEnvironmentID(id)
	return nc
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (nc *NetworkCreate) SetNillableEnvironmentID(id *uuid.UUID) *NetworkCreate {
	if id != nil {
		nc = nc.SetEnvironmentID(*id)
	}
	return nc
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (nc *NetworkCreate) SetEnvironment(e *Environment) *NetworkCreate {
	return nc.SetEnvironmentID(e.ID)
}

// AddHostDependencyIDs adds the "HostDependencies" edge to the HostDependency entity by IDs.
func (nc *NetworkCreate) AddHostDependencyIDs(ids ...uuid.UUID) *NetworkCreate {
	nc.mutation.AddHostDependencyIDs(ids...)
	return nc
}

// AddHostDependencies adds the "HostDependencies" edges to the HostDependency entity.
func (nc *NetworkCreate) AddHostDependencies(h ...*HostDependency) *NetworkCreate {
	ids := make([]uuid.UUID, len(h))
	for i := range h {
		ids[i] = h[i].ID
	}
	return nc.AddHostDependencyIDs(ids...)
}

// AddIncludedNetworkIDs adds the "IncludedNetworks" edge to the IncludedNetwork entity by IDs.
func (nc *NetworkCreate) AddIncludedNetworkIDs(ids ...uuid.UUID) *NetworkCreate {
	nc.mutation.AddIncludedNetworkIDs(ids...)
	return nc
}

// AddIncludedNetworks adds the "IncludedNetworks" edges to the IncludedNetwork entity.
func (nc *NetworkCreate) AddIncludedNetworks(i ...*IncludedNetwork) *NetworkCreate {
	ids := make([]uuid.UUID, len(i))
	for j := range i {
		ids[j] = i[j].ID
	}
	return nc.AddIncludedNetworkIDs(ids...)
}

// Mutation returns the NetworkMutation object of the builder.
func (nc *NetworkCreate) Mutation() *NetworkMutation {
	return nc.mutation
}

// Save creates the Network in the database.
func (nc *NetworkCreate) Save(ctx context.Context) (*Network, error) {
	nc.defaults()
	return withHooks(ctx, nc.sqlSave, nc.mutation, nc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (nc *NetworkCreate) SaveX(ctx context.Context) *Network {
	v, err := nc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (nc *NetworkCreate) Exec(ctx context.Context) error {
	_, err := nc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (nc *NetworkCreate) ExecX(ctx context.Context) {
	if err := nc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (nc *NetworkCreate) defaults() {
	if _, ok := nc.mutation.ID(); !ok {
		v := network.DefaultID()
		nc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (nc *NetworkCreate) check() error {
	if _, ok := nc.mutation.HCLID(); !ok {
		return &ValidationError{Name: "hcl_id", err: errors.New(`ent: missing required field "Network.hcl_id"`)}
	}
	if _, ok := nc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Network.name"`)}
	}
	if _, ok := nc.mutation.Cidr(); !ok {
		return &ValidationError{Name: "cidr", err: errors.New(`ent: missing required field "Network.cidr"`)}
	}
	if _, ok := nc.mutation.VdiVisible(); !ok {
		return &ValidationError{Name: "vdi_visible", err: errors.New(`ent: missing required field "Network.vdi_visible"`)}
	}
	if _, ok := nc.mutation.Vars(); !ok {
		return &ValidationError{Name: "vars", err: errors.New(`ent: missing required field "Network.vars"`)}
	}
	if _, ok := nc.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New(`ent: missing required field "Network.tags"`)}
	}
	return nil
}

func (nc *NetworkCreate) sqlSave(ctx context.Context) (*Network, error) {
	if err := nc.check(); err != nil {
		return nil, err
	}
	_node, _spec := nc.createSpec()
	if err := sqlgraph.CreateNode(ctx, nc.driver, _spec); err != nil {
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
	nc.mutation.id = &_node.ID
	nc.mutation.done = true
	return _node, nil
}

func (nc *NetworkCreate) createSpec() (*Network, *sqlgraph.CreateSpec) {
	var (
		_node = &Network{config: nc.config}
		_spec = sqlgraph.NewCreateSpec(network.Table, sqlgraph.NewFieldSpec(network.FieldID, field.TypeUUID))
	)
	if id, ok := nc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := nc.mutation.HCLID(); ok {
		_spec.SetField(network.FieldHCLID, field.TypeString, value)
		_node.HCLID = value
	}
	if value, ok := nc.mutation.Name(); ok {
		_spec.SetField(network.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := nc.mutation.Cidr(); ok {
		_spec.SetField(network.FieldCidr, field.TypeString, value)
		_node.Cidr = value
	}
	if value, ok := nc.mutation.VdiVisible(); ok {
		_spec.SetField(network.FieldVdiVisible, field.TypeBool, value)
		_node.VdiVisible = value
	}
	if value, ok := nc.mutation.Vars(); ok {
		_spec.SetField(network.FieldVars, field.TypeJSON, value)
		_node.Vars = value
	}
	if value, ok := nc.mutation.Tags(); ok {
		_spec.SetField(network.FieldTags, field.TypeJSON, value)
		_node.Tags = value
	}
	if nodes := nc.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   network.EnvironmentTable,
			Columns: []string{network.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(environment.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.environment_networks = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := nc.mutation.HostDependenciesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   network.HostDependenciesTable,
			Columns: []string{network.HostDependenciesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(hostdependency.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := nc.mutation.IncludedNetworksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   network.IncludedNetworksTable,
			Columns: []string{network.IncludedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(includednetwork.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// NetworkCreateBulk is the builder for creating many Network entities in bulk.
type NetworkCreateBulk struct {
	config
	builders []*NetworkCreate
}

// Save creates the Network entities in the database.
func (ncb *NetworkCreateBulk) Save(ctx context.Context) ([]*Network, error) {
	specs := make([]*sqlgraph.CreateSpec, len(ncb.builders))
	nodes := make([]*Network, len(ncb.builders))
	mutators := make([]Mutator, len(ncb.builders))
	for i := range ncb.builders {
		func(i int, root context.Context) {
			builder := ncb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*NetworkMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, ncb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ncb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, ncb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ncb *NetworkCreateBulk) SaveX(ctx context.Context) []*Network {
	v, err := ncb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ncb *NetworkCreateBulk) Exec(ctx context.Context) error {
	_, err := ncb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ncb *NetworkCreateBulk) ExecX(ctx context.Context) {
	if err := ncb.Exec(ctx); err != nil {
		panic(err)
	}
}
