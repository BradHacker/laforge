// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/validation"
)

// ValidationDelete is the builder for deleting a Validation entity.
type ValidationDelete struct {
	config
	hooks    []Hook
	mutation *ValidationMutation
}

// Where appends a list predicates to the ValidationDelete builder.
func (vd *ValidationDelete) Where(ps ...predicate.Validation) *ValidationDelete {
	vd.mutation.Where(ps...)
	return vd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (vd *ValidationDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(vd.hooks) == 0 {
		affected, err = vd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*ValidationMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			vd.mutation = mutation
			affected, err = vd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(vd.hooks) - 1; i >= 0; i-- {
			if vd.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = vd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, vd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (vd *ValidationDelete) ExecX(ctx context.Context) int {
	n, err := vd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (vd *ValidationDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: validation.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: validation.FieldID,
			},
		},
	}
	if ps := vd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, vd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	return affected, err
}

// ValidationDeleteOne is the builder for deleting a single Validation entity.
type ValidationDeleteOne struct {
	vd *ValidationDelete
}

// Exec executes the deletion query.
func (vdo *ValidationDeleteOne) Exec(ctx context.Context) error {
	n, err := vdo.vd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{validation.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (vdo *ValidationDeleteOne) ExecX(ctx context.Context) {
	vdo.vd.ExecX(ctx)
}
