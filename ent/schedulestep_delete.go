// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/schedulestep"
)

// ScheduleStepDelete is the builder for deleting a ScheduleStep entity.
type ScheduleStepDelete struct {
	config
	hooks    []Hook
	mutation *ScheduleStepMutation
}

// Where appends a list predicates to the ScheduleStepDelete builder.
func (ssd *ScheduleStepDelete) Where(ps ...predicate.ScheduleStep) *ScheduleStepDelete {
	ssd.mutation.Where(ps...)
	return ssd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (ssd *ScheduleStepDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(ssd.hooks) == 0 {
		affected, err = ssd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*ScheduleStepMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			ssd.mutation = mutation
			affected, err = ssd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(ssd.hooks) - 1; i >= 0; i-- {
			if ssd.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = ssd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, ssd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (ssd *ScheduleStepDelete) ExecX(ctx context.Context) int {
	n, err := ssd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (ssd *ScheduleStepDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: schedulestep.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: schedulestep.FieldID,
			},
		},
	}
	if ps := ssd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, ssd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	return affected, err
}

// ScheduleStepDeleteOne is the builder for deleting a single ScheduleStep entity.
type ScheduleStepDeleteOne struct {
	ssd *ScheduleStepDelete
}

// Exec executes the deletion query.
func (ssdo *ScheduleStepDeleteOne) Exec(ctx context.Context) error {
	n, err := ssdo.ssd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{schedulestep.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (ssdo *ScheduleStepDeleteOne) ExecX(ctx context.Context) {
	ssdo.ssd.ExecX(ctx)
}
