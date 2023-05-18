// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/hostdependency"
	"github.com/gen0cide/laforge/ent/network"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/google/uuid"
)

// HostDependencyUpdate is the builder for updating HostDependency entities.
type HostDependencyUpdate struct {
	config
	hooks    []Hook
	mutation *HostDependencyMutation
}

// Where appends a list predicates to the HostDependencyUpdate builder.
func (hdu *HostDependencyUpdate) Where(ps ...predicate.HostDependency) *HostDependencyUpdate {
	hdu.mutation.Where(ps...)
	return hdu
}

// SetHostID sets the "host_id" field.
func (hdu *HostDependencyUpdate) SetHostID(s string) *HostDependencyUpdate {
	hdu.mutation.SetHostID(s)
	return hdu
}

// SetNetworkID sets the "network_id" field.
func (hdu *HostDependencyUpdate) SetNetworkID(s string) *HostDependencyUpdate {
	hdu.mutation.SetNetworkID(s)
	return hdu
}

// SetRequiredByID sets the "RequiredBy" edge to the Host entity by ID.
func (hdu *HostDependencyUpdate) SetRequiredByID(id uuid.UUID) *HostDependencyUpdate {
	hdu.mutation.SetRequiredByID(id)
	return hdu
}

// SetNillableRequiredByID sets the "RequiredBy" edge to the Host entity by ID if the given value is not nil.
func (hdu *HostDependencyUpdate) SetNillableRequiredByID(id *uuid.UUID) *HostDependencyUpdate {
	if id != nil {
		hdu = hdu.SetRequiredByID(*id)
	}
	return hdu
}

// SetRequiredBy sets the "RequiredBy" edge to the Host entity.
func (hdu *HostDependencyUpdate) SetRequiredBy(h *Host) *HostDependencyUpdate {
	return hdu.SetRequiredByID(h.ID)
}

// SetDependOnHostID sets the "DependOnHost" edge to the Host entity by ID.
func (hdu *HostDependencyUpdate) SetDependOnHostID(id uuid.UUID) *HostDependencyUpdate {
	hdu.mutation.SetDependOnHostID(id)
	return hdu
}

// SetNillableDependOnHostID sets the "DependOnHost" edge to the Host entity by ID if the given value is not nil.
func (hdu *HostDependencyUpdate) SetNillableDependOnHostID(id *uuid.UUID) *HostDependencyUpdate {
	if id != nil {
		hdu = hdu.SetDependOnHostID(*id)
	}
	return hdu
}

// SetDependOnHost sets the "DependOnHost" edge to the Host entity.
func (hdu *HostDependencyUpdate) SetDependOnHost(h *Host) *HostDependencyUpdate {
	return hdu.SetDependOnHostID(h.ID)
}

// SetDependOnNetworkID sets the "DependOnNetwork" edge to the Network entity by ID.
func (hdu *HostDependencyUpdate) SetDependOnNetworkID(id uuid.UUID) *HostDependencyUpdate {
	hdu.mutation.SetDependOnNetworkID(id)
	return hdu
}

// SetNillableDependOnNetworkID sets the "DependOnNetwork" edge to the Network entity by ID if the given value is not nil.
func (hdu *HostDependencyUpdate) SetNillableDependOnNetworkID(id *uuid.UUID) *HostDependencyUpdate {
	if id != nil {
		hdu = hdu.SetDependOnNetworkID(*id)
	}
	return hdu
}

// SetDependOnNetwork sets the "DependOnNetwork" edge to the Network entity.
func (hdu *HostDependencyUpdate) SetDependOnNetwork(n *Network) *HostDependencyUpdate {
	return hdu.SetDependOnNetworkID(n.ID)
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (hdu *HostDependencyUpdate) SetEnvironmentID(id uuid.UUID) *HostDependencyUpdate {
	hdu.mutation.SetEnvironmentID(id)
	return hdu
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (hdu *HostDependencyUpdate) SetNillableEnvironmentID(id *uuid.UUID) *HostDependencyUpdate {
	if id != nil {
		hdu = hdu.SetEnvironmentID(*id)
	}
	return hdu
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (hdu *HostDependencyUpdate) SetEnvironment(e *Environment) *HostDependencyUpdate {
	return hdu.SetEnvironmentID(e.ID)
}

// Mutation returns the HostDependencyMutation object of the builder.
func (hdu *HostDependencyUpdate) Mutation() *HostDependencyMutation {
	return hdu.mutation
}

// ClearRequiredBy clears the "RequiredBy" edge to the Host entity.
func (hdu *HostDependencyUpdate) ClearRequiredBy() *HostDependencyUpdate {
	hdu.mutation.ClearRequiredBy()
	return hdu
}

// ClearDependOnHost clears the "DependOnHost" edge to the Host entity.
func (hdu *HostDependencyUpdate) ClearDependOnHost() *HostDependencyUpdate {
	hdu.mutation.ClearDependOnHost()
	return hdu
}

// ClearDependOnNetwork clears the "DependOnNetwork" edge to the Network entity.
func (hdu *HostDependencyUpdate) ClearDependOnNetwork() *HostDependencyUpdate {
	hdu.mutation.ClearDependOnNetwork()
	return hdu
}

// ClearEnvironment clears the "Environment" edge to the Environment entity.
func (hdu *HostDependencyUpdate) ClearEnvironment() *HostDependencyUpdate {
	hdu.mutation.ClearEnvironment()
	return hdu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (hdu *HostDependencyUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, hdu.sqlSave, hdu.mutation, hdu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (hdu *HostDependencyUpdate) SaveX(ctx context.Context) int {
	affected, err := hdu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (hdu *HostDependencyUpdate) Exec(ctx context.Context) error {
	_, err := hdu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (hdu *HostDependencyUpdate) ExecX(ctx context.Context) {
	if err := hdu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (hdu *HostDependencyUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(hostdependency.Table, hostdependency.Columns, sqlgraph.NewFieldSpec(hostdependency.FieldID, field.TypeUUID))
	if ps := hdu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := hdu.mutation.HostID(); ok {
		_spec.SetField(hostdependency.FieldHostID, field.TypeString, value)
	}
	if value, ok := hdu.mutation.NetworkID(); ok {
		_spec.SetField(hostdependency.FieldNetworkID, field.TypeString, value)
	}
	if hdu.mutation.RequiredByCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.RequiredByTable,
			Columns: []string{hostdependency.RequiredByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hdu.mutation.RequiredByIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.RequiredByTable,
			Columns: []string{hostdependency.RequiredByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if hdu.mutation.DependOnHostCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnHostTable,
			Columns: []string{hostdependency.DependOnHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hdu.mutation.DependOnHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnHostTable,
			Columns: []string{hostdependency.DependOnHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if hdu.mutation.DependOnNetworkCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnNetworkTable,
			Columns: []string{hostdependency.DependOnNetworkColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(network.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hdu.mutation.DependOnNetworkIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnNetworkTable,
			Columns: []string{hostdependency.DependOnNetworkColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(network.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if hdu.mutation.EnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   hostdependency.EnvironmentTable,
			Columns: []string{hostdependency.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(environment.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hdu.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   hostdependency.EnvironmentTable,
			Columns: []string{hostdependency.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(environment.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, hdu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{hostdependency.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	hdu.mutation.done = true
	return n, nil
}

// HostDependencyUpdateOne is the builder for updating a single HostDependency entity.
type HostDependencyUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *HostDependencyMutation
}

// SetHostID sets the "host_id" field.
func (hduo *HostDependencyUpdateOne) SetHostID(s string) *HostDependencyUpdateOne {
	hduo.mutation.SetHostID(s)
	return hduo
}

// SetNetworkID sets the "network_id" field.
func (hduo *HostDependencyUpdateOne) SetNetworkID(s string) *HostDependencyUpdateOne {
	hduo.mutation.SetNetworkID(s)
	return hduo
}

// SetRequiredByID sets the "RequiredBy" edge to the Host entity by ID.
func (hduo *HostDependencyUpdateOne) SetRequiredByID(id uuid.UUID) *HostDependencyUpdateOne {
	hduo.mutation.SetRequiredByID(id)
	return hduo
}

// SetNillableRequiredByID sets the "RequiredBy" edge to the Host entity by ID if the given value is not nil.
func (hduo *HostDependencyUpdateOne) SetNillableRequiredByID(id *uuid.UUID) *HostDependencyUpdateOne {
	if id != nil {
		hduo = hduo.SetRequiredByID(*id)
	}
	return hduo
}

// SetRequiredBy sets the "RequiredBy" edge to the Host entity.
func (hduo *HostDependencyUpdateOne) SetRequiredBy(h *Host) *HostDependencyUpdateOne {
	return hduo.SetRequiredByID(h.ID)
}

// SetDependOnHostID sets the "DependOnHost" edge to the Host entity by ID.
func (hduo *HostDependencyUpdateOne) SetDependOnHostID(id uuid.UUID) *HostDependencyUpdateOne {
	hduo.mutation.SetDependOnHostID(id)
	return hduo
}

// SetNillableDependOnHostID sets the "DependOnHost" edge to the Host entity by ID if the given value is not nil.
func (hduo *HostDependencyUpdateOne) SetNillableDependOnHostID(id *uuid.UUID) *HostDependencyUpdateOne {
	if id != nil {
		hduo = hduo.SetDependOnHostID(*id)
	}
	return hduo
}

// SetDependOnHost sets the "DependOnHost" edge to the Host entity.
func (hduo *HostDependencyUpdateOne) SetDependOnHost(h *Host) *HostDependencyUpdateOne {
	return hduo.SetDependOnHostID(h.ID)
}

// SetDependOnNetworkID sets the "DependOnNetwork" edge to the Network entity by ID.
func (hduo *HostDependencyUpdateOne) SetDependOnNetworkID(id uuid.UUID) *HostDependencyUpdateOne {
	hduo.mutation.SetDependOnNetworkID(id)
	return hduo
}

// SetNillableDependOnNetworkID sets the "DependOnNetwork" edge to the Network entity by ID if the given value is not nil.
func (hduo *HostDependencyUpdateOne) SetNillableDependOnNetworkID(id *uuid.UUID) *HostDependencyUpdateOne {
	if id != nil {
		hduo = hduo.SetDependOnNetworkID(*id)
	}
	return hduo
}

// SetDependOnNetwork sets the "DependOnNetwork" edge to the Network entity.
func (hduo *HostDependencyUpdateOne) SetDependOnNetwork(n *Network) *HostDependencyUpdateOne {
	return hduo.SetDependOnNetworkID(n.ID)
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (hduo *HostDependencyUpdateOne) SetEnvironmentID(id uuid.UUID) *HostDependencyUpdateOne {
	hduo.mutation.SetEnvironmentID(id)
	return hduo
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (hduo *HostDependencyUpdateOne) SetNillableEnvironmentID(id *uuid.UUID) *HostDependencyUpdateOne {
	if id != nil {
		hduo = hduo.SetEnvironmentID(*id)
	}
	return hduo
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (hduo *HostDependencyUpdateOne) SetEnvironment(e *Environment) *HostDependencyUpdateOne {
	return hduo.SetEnvironmentID(e.ID)
}

// Mutation returns the HostDependencyMutation object of the builder.
func (hduo *HostDependencyUpdateOne) Mutation() *HostDependencyMutation {
	return hduo.mutation
}

// ClearRequiredBy clears the "RequiredBy" edge to the Host entity.
func (hduo *HostDependencyUpdateOne) ClearRequiredBy() *HostDependencyUpdateOne {
	hduo.mutation.ClearRequiredBy()
	return hduo
}

// ClearDependOnHost clears the "DependOnHost" edge to the Host entity.
func (hduo *HostDependencyUpdateOne) ClearDependOnHost() *HostDependencyUpdateOne {
	hduo.mutation.ClearDependOnHost()
	return hduo
}

// ClearDependOnNetwork clears the "DependOnNetwork" edge to the Network entity.
func (hduo *HostDependencyUpdateOne) ClearDependOnNetwork() *HostDependencyUpdateOne {
	hduo.mutation.ClearDependOnNetwork()
	return hduo
}

// ClearEnvironment clears the "Environment" edge to the Environment entity.
func (hduo *HostDependencyUpdateOne) ClearEnvironment() *HostDependencyUpdateOne {
	hduo.mutation.ClearEnvironment()
	return hduo
}

// Where appends a list predicates to the HostDependencyUpdate builder.
func (hduo *HostDependencyUpdateOne) Where(ps ...predicate.HostDependency) *HostDependencyUpdateOne {
	hduo.mutation.Where(ps...)
	return hduo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (hduo *HostDependencyUpdateOne) Select(field string, fields ...string) *HostDependencyUpdateOne {
	hduo.fields = append([]string{field}, fields...)
	return hduo
}

// Save executes the query and returns the updated HostDependency entity.
func (hduo *HostDependencyUpdateOne) Save(ctx context.Context) (*HostDependency, error) {
	return withHooks(ctx, hduo.sqlSave, hduo.mutation, hduo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (hduo *HostDependencyUpdateOne) SaveX(ctx context.Context) *HostDependency {
	node, err := hduo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (hduo *HostDependencyUpdateOne) Exec(ctx context.Context) error {
	_, err := hduo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (hduo *HostDependencyUpdateOne) ExecX(ctx context.Context) {
	if err := hduo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (hduo *HostDependencyUpdateOne) sqlSave(ctx context.Context) (_node *HostDependency, err error) {
	_spec := sqlgraph.NewUpdateSpec(hostdependency.Table, hostdependency.Columns, sqlgraph.NewFieldSpec(hostdependency.FieldID, field.TypeUUID))
	id, ok := hduo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "HostDependency.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := hduo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, hostdependency.FieldID)
		for _, f := range fields {
			if !hostdependency.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != hostdependency.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := hduo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := hduo.mutation.HostID(); ok {
		_spec.SetField(hostdependency.FieldHostID, field.TypeString, value)
	}
	if value, ok := hduo.mutation.NetworkID(); ok {
		_spec.SetField(hostdependency.FieldNetworkID, field.TypeString, value)
	}
	if hduo.mutation.RequiredByCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.RequiredByTable,
			Columns: []string{hostdependency.RequiredByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hduo.mutation.RequiredByIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.RequiredByTable,
			Columns: []string{hostdependency.RequiredByColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if hduo.mutation.DependOnHostCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnHostTable,
			Columns: []string{hostdependency.DependOnHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hduo.mutation.DependOnHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnHostTable,
			Columns: []string{hostdependency.DependOnHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if hduo.mutation.DependOnNetworkCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnNetworkTable,
			Columns: []string{hostdependency.DependOnNetworkColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(network.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hduo.mutation.DependOnNetworkIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   hostdependency.DependOnNetworkTable,
			Columns: []string{hostdependency.DependOnNetworkColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(network.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if hduo.mutation.EnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   hostdependency.EnvironmentTable,
			Columns: []string{hostdependency.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(environment.FieldID, field.TypeUUID),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := hduo.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   hostdependency.EnvironmentTable,
			Columns: []string{hostdependency.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(environment.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &HostDependency{config: hduo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, hduo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{hostdependency.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	hduo.mutation.done = true
	return _node, nil
}
