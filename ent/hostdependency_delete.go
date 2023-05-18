// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/hostdependency"
	"github.com/gen0cide/laforge/ent/predicate"
)

// HostDependencyDelete is the builder for deleting a HostDependency entity.
type HostDependencyDelete struct {
	config
	hooks    []Hook
	mutation *HostDependencyMutation
}

// Where appends a list predicates to the HostDependencyDelete builder.
func (hdd *HostDependencyDelete) Where(ps ...predicate.HostDependency) *HostDependencyDelete {
	hdd.mutation.Where(ps...)
	return hdd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (hdd *HostDependencyDelete) Exec(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(hdd.hooks) == 0 {
		affected, err = hdd.sqlExec(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*HostDependencyMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			hdd.mutation = mutation
			affected, err = hdd.sqlExec(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(hdd.hooks) - 1; i >= 0; i-- {
			if hdd.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = hdd.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, hdd.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// ExecX is like Exec, but panics if an error occurs.
func (hdd *HostDependencyDelete) ExecX(ctx context.Context) int {
	n, err := hdd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (hdd *HostDependencyDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := &sqlgraph.DeleteSpec{
		Node: &sqlgraph.NodeSpec{
			Table: hostdependency.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: hostdependency.FieldID,
			},
		},
	}
	if ps := hdd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, hdd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	return affected, err
}

// HostDependencyDeleteOne is the builder for deleting a single HostDependency entity.
type HostDependencyDeleteOne struct {
	hdd *HostDependencyDelete
}

// Exec executes the deletion query.
func (hddo *HostDependencyDeleteOne) Exec(ctx context.Context) error {
	n, err := hddo.hdd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{hostdependency.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (hddo *HostDependencyDeleteOne) ExecX(ctx context.Context) {
	hddo.hdd.ExecX(ctx)
}
