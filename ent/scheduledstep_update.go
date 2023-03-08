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
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/scheduledstep"
	"github.com/google/uuid"
)

// ScheduledStepUpdate is the builder for updating ScheduledStep entities.
type ScheduledStepUpdate struct {
	config
	hooks    []Hook
	mutation *ScheduledStepMutation
}

// Where appends a list predicates to the ScheduledStepUpdate builder.
func (ssu *ScheduledStepUpdate) Where(ps ...predicate.ScheduledStep) *ScheduledStepUpdate {
	ssu.mutation.Where(ps...)
	return ssu
}

// SetHclID sets the "hcl_id" field.
func (ssu *ScheduledStepUpdate) SetHclID(s string) *ScheduledStepUpdate {
	ssu.mutation.SetHclID(s)
	return ssu
}

// SetName sets the "name" field.
func (ssu *ScheduledStepUpdate) SetName(s string) *ScheduledStepUpdate {
	ssu.mutation.SetName(s)
	return ssu
}

// SetDescription sets the "description" field.
func (ssu *ScheduledStepUpdate) SetDescription(s string) *ScheduledStepUpdate {
	ssu.mutation.SetDescription(s)
	return ssu
}

// SetStep sets the "step" field.
func (ssu *ScheduledStepUpdate) SetStep(s string) *ScheduledStepUpdate {
	ssu.mutation.SetStep(s)
	return ssu
}

// SetType sets the "type" field.
func (ssu *ScheduledStepUpdate) SetType(s scheduledstep.Type) *ScheduledStepUpdate {
	ssu.mutation.SetType(s)
	return ssu
}

// SetSchedule sets the "schedule" field.
func (ssu *ScheduledStepUpdate) SetSchedule(s string) *ScheduledStepUpdate {
	ssu.mutation.SetSchedule(s)
	return ssu
}

// SetRunAt sets the "run_at" field.
func (ssu *ScheduledStepUpdate) SetRunAt(s string) *ScheduledStepUpdate {
	ssu.mutation.SetRunAt(s)
	return ssu
}

// SetScheduledStepToEnvironmentID sets the "ScheduledStepToEnvironment" edge to the Environment entity by ID.
func (ssu *ScheduledStepUpdate) SetScheduledStepToEnvironmentID(id uuid.UUID) *ScheduledStepUpdate {
	ssu.mutation.SetScheduledStepToEnvironmentID(id)
	return ssu
}

// SetNillableScheduledStepToEnvironmentID sets the "ScheduledStepToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (ssu *ScheduledStepUpdate) SetNillableScheduledStepToEnvironmentID(id *uuid.UUID) *ScheduledStepUpdate {
	if id != nil {
		ssu = ssu.SetScheduledStepToEnvironmentID(*id)
	}
	return ssu
}

// SetScheduledStepToEnvironment sets the "ScheduledStepToEnvironment" edge to the Environment entity.
func (ssu *ScheduledStepUpdate) SetScheduledStepToEnvironment(e *Environment) *ScheduledStepUpdate {
	return ssu.SetScheduledStepToEnvironmentID(e.ID)
}

// Mutation returns the ScheduledStepMutation object of the builder.
func (ssu *ScheduledStepUpdate) Mutation() *ScheduledStepMutation {
	return ssu.mutation
}

// ClearScheduledStepToEnvironment clears the "ScheduledStepToEnvironment" edge to the Environment entity.
func (ssu *ScheduledStepUpdate) ClearScheduledStepToEnvironment() *ScheduledStepUpdate {
	ssu.mutation.ClearScheduledStepToEnvironment()
	return ssu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (ssu *ScheduledStepUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(ssu.hooks) == 0 {
		if err = ssu.check(); err != nil {
			return 0, err
		}
		affected, err = ssu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*ScheduledStepMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = ssu.check(); err != nil {
				return 0, err
			}
			ssu.mutation = mutation
			affected, err = ssu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(ssu.hooks) - 1; i >= 0; i-- {
			if ssu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = ssu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, ssu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (ssu *ScheduledStepUpdate) SaveX(ctx context.Context) int {
	affected, err := ssu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (ssu *ScheduledStepUpdate) Exec(ctx context.Context) error {
	_, err := ssu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ssu *ScheduledStepUpdate) ExecX(ctx context.Context) {
	if err := ssu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ssu *ScheduledStepUpdate) check() error {
	if v, ok := ssu.mutation.GetType(); ok {
		if err := scheduledstep.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "ScheduledStep.type": %w`, err)}
		}
	}
	return nil
}

func (ssu *ScheduledStepUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   scheduledstep.Table,
			Columns: scheduledstep.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: scheduledstep.FieldID,
			},
		},
	}
	if ps := ssu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ssu.mutation.HclID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldHclID,
		})
	}
	if value, ok := ssu.mutation.Name(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldName,
		})
	}
	if value, ok := ssu.mutation.Description(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldDescription,
		})
	}
	if value, ok := ssu.mutation.Step(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldStep,
		})
	}
	if value, ok := ssu.mutation.GetType(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: scheduledstep.FieldType,
		})
	}
	if value, ok := ssu.mutation.Schedule(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldSchedule,
		})
	}
	if value, ok := ssu.mutation.RunAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldRunAt,
		})
	}
	if ssu.mutation.ScheduledStepToEnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   scheduledstep.ScheduledStepToEnvironmentTable,
			Columns: []string{scheduledstep.ScheduledStepToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ssu.mutation.ScheduledStepToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   scheduledstep.ScheduledStepToEnvironmentTable,
			Columns: []string{scheduledstep.ScheduledStepToEnvironmentColumn},
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, ssu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{scheduledstep.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// ScheduledStepUpdateOne is the builder for updating a single ScheduledStep entity.
type ScheduledStepUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *ScheduledStepMutation
}

// SetHclID sets the "hcl_id" field.
func (ssuo *ScheduledStepUpdateOne) SetHclID(s string) *ScheduledStepUpdateOne {
	ssuo.mutation.SetHclID(s)
	return ssuo
}

// SetName sets the "name" field.
func (ssuo *ScheduledStepUpdateOne) SetName(s string) *ScheduledStepUpdateOne {
	ssuo.mutation.SetName(s)
	return ssuo
}

// SetDescription sets the "description" field.
func (ssuo *ScheduledStepUpdateOne) SetDescription(s string) *ScheduledStepUpdateOne {
	ssuo.mutation.SetDescription(s)
	return ssuo
}

// SetStep sets the "step" field.
func (ssuo *ScheduledStepUpdateOne) SetStep(s string) *ScheduledStepUpdateOne {
	ssuo.mutation.SetStep(s)
	return ssuo
}

// SetType sets the "type" field.
func (ssuo *ScheduledStepUpdateOne) SetType(s scheduledstep.Type) *ScheduledStepUpdateOne {
	ssuo.mutation.SetType(s)
	return ssuo
}

// SetSchedule sets the "schedule" field.
func (ssuo *ScheduledStepUpdateOne) SetSchedule(s string) *ScheduledStepUpdateOne {
	ssuo.mutation.SetSchedule(s)
	return ssuo
}

// SetRunAt sets the "run_at" field.
func (ssuo *ScheduledStepUpdateOne) SetRunAt(s string) *ScheduledStepUpdateOne {
	ssuo.mutation.SetRunAt(s)
	return ssuo
}

// SetScheduledStepToEnvironmentID sets the "ScheduledStepToEnvironment" edge to the Environment entity by ID.
func (ssuo *ScheduledStepUpdateOne) SetScheduledStepToEnvironmentID(id uuid.UUID) *ScheduledStepUpdateOne {
	ssuo.mutation.SetScheduledStepToEnvironmentID(id)
	return ssuo
}

// SetNillableScheduledStepToEnvironmentID sets the "ScheduledStepToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (ssuo *ScheduledStepUpdateOne) SetNillableScheduledStepToEnvironmentID(id *uuid.UUID) *ScheduledStepUpdateOne {
	if id != nil {
		ssuo = ssuo.SetScheduledStepToEnvironmentID(*id)
	}
	return ssuo
}

// SetScheduledStepToEnvironment sets the "ScheduledStepToEnvironment" edge to the Environment entity.
func (ssuo *ScheduledStepUpdateOne) SetScheduledStepToEnvironment(e *Environment) *ScheduledStepUpdateOne {
	return ssuo.SetScheduledStepToEnvironmentID(e.ID)
}

// Mutation returns the ScheduledStepMutation object of the builder.
func (ssuo *ScheduledStepUpdateOne) Mutation() *ScheduledStepMutation {
	return ssuo.mutation
}

// ClearScheduledStepToEnvironment clears the "ScheduledStepToEnvironment" edge to the Environment entity.
func (ssuo *ScheduledStepUpdateOne) ClearScheduledStepToEnvironment() *ScheduledStepUpdateOne {
	ssuo.mutation.ClearScheduledStepToEnvironment()
	return ssuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (ssuo *ScheduledStepUpdateOne) Select(field string, fields ...string) *ScheduledStepUpdateOne {
	ssuo.fields = append([]string{field}, fields...)
	return ssuo
}

// Save executes the query and returns the updated ScheduledStep entity.
func (ssuo *ScheduledStepUpdateOne) Save(ctx context.Context) (*ScheduledStep, error) {
	var (
		err  error
		node *ScheduledStep
	)
	if len(ssuo.hooks) == 0 {
		if err = ssuo.check(); err != nil {
			return nil, err
		}
		node, err = ssuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*ScheduledStepMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = ssuo.check(); err != nil {
				return nil, err
			}
			ssuo.mutation = mutation
			node, err = ssuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(ssuo.hooks) - 1; i >= 0; i-- {
			if ssuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = ssuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, ssuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*ScheduledStep)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from ScheduledStepMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (ssuo *ScheduledStepUpdateOne) SaveX(ctx context.Context) *ScheduledStep {
	node, err := ssuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (ssuo *ScheduledStepUpdateOne) Exec(ctx context.Context) error {
	_, err := ssuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ssuo *ScheduledStepUpdateOne) ExecX(ctx context.Context) {
	if err := ssuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ssuo *ScheduledStepUpdateOne) check() error {
	if v, ok := ssuo.mutation.GetType(); ok {
		if err := scheduledstep.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "ScheduledStep.type": %w`, err)}
		}
	}
	return nil
}

func (ssuo *ScheduledStepUpdateOne) sqlSave(ctx context.Context) (_node *ScheduledStep, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   scheduledstep.Table,
			Columns: scheduledstep.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: scheduledstep.FieldID,
			},
		},
	}
	id, ok := ssuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "ScheduledStep.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := ssuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, scheduledstep.FieldID)
		for _, f := range fields {
			if !scheduledstep.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != scheduledstep.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := ssuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ssuo.mutation.HclID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldHclID,
		})
	}
	if value, ok := ssuo.mutation.Name(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldName,
		})
	}
	if value, ok := ssuo.mutation.Description(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldDescription,
		})
	}
	if value, ok := ssuo.mutation.Step(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldStep,
		})
	}
	if value, ok := ssuo.mutation.GetType(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: scheduledstep.FieldType,
		})
	}
	if value, ok := ssuo.mutation.Schedule(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldSchedule,
		})
	}
	if value, ok := ssuo.mutation.RunAt(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: scheduledstep.FieldRunAt,
		})
	}
	if ssuo.mutation.ScheduledStepToEnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   scheduledstep.ScheduledStepToEnvironmentTable,
			Columns: []string{scheduledstep.ScheduledStepToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ssuo.mutation.ScheduledStepToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   scheduledstep.ScheduledStepToEnvironmentTable,
			Columns: []string{scheduledstep.ScheduledStepToEnvironmentColumn},
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &ScheduledStep{config: ssuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, ssuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{scheduledstep.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
