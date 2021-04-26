// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/filedelete"
	"github.com/gen0cide/laforge/ent/predicate"
)

// FileDeleteUpdate is the builder for updating FileDelete entities.
type FileDeleteUpdate struct {
	config
	hooks    []Hook
	mutation *FileDeleteMutation
}

// Where adds a new predicate for the FileDeleteUpdate builder.
func (fdu *FileDeleteUpdate) Where(ps ...predicate.FileDelete) *FileDeleteUpdate {
	fdu.mutation.predicates = append(fdu.mutation.predicates, ps...)
	return fdu
}

// SetHclID sets the "hcl_id" field.
func (fdu *FileDeleteUpdate) SetHclID(s string) *FileDeleteUpdate {
	fdu.mutation.SetHclID(s)
	return fdu
}

// SetPath sets the "path" field.
func (fdu *FileDeleteUpdate) SetPath(s string) *FileDeleteUpdate {
	fdu.mutation.SetPath(s)
	return fdu
}

// SetTags sets the "tags" field.
func (fdu *FileDeleteUpdate) SetTags(m map[string]string) *FileDeleteUpdate {
	fdu.mutation.SetTags(m)
	return fdu
}

// SetFileDeleteToEnvironmentID sets the "FileDeleteToEnvironment" edge to the Environment entity by ID.
func (fdu *FileDeleteUpdate) SetFileDeleteToEnvironmentID(id int) *FileDeleteUpdate {
	fdu.mutation.SetFileDeleteToEnvironmentID(id)
	return fdu
}

// SetNillableFileDeleteToEnvironmentID sets the "FileDeleteToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (fdu *FileDeleteUpdate) SetNillableFileDeleteToEnvironmentID(id *int) *FileDeleteUpdate {
	if id != nil {
		fdu = fdu.SetFileDeleteToEnvironmentID(*id)
	}
	return fdu
}

// SetFileDeleteToEnvironment sets the "FileDeleteToEnvironment" edge to the Environment entity.
func (fdu *FileDeleteUpdate) SetFileDeleteToEnvironment(e *Environment) *FileDeleteUpdate {
	return fdu.SetFileDeleteToEnvironmentID(e.ID)
}

// Mutation returns the FileDeleteMutation object of the builder.
func (fdu *FileDeleteUpdate) Mutation() *FileDeleteMutation {
	return fdu.mutation
}

// ClearFileDeleteToEnvironment clears the "FileDeleteToEnvironment" edge to the Environment entity.
func (fdu *FileDeleteUpdate) ClearFileDeleteToEnvironment() *FileDeleteUpdate {
	fdu.mutation.ClearFileDeleteToEnvironment()
	return fdu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (fdu *FileDeleteUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(fdu.hooks) == 0 {
		affected, err = fdu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*FileDeleteMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			fdu.mutation = mutation
			affected, err = fdu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(fdu.hooks) - 1; i >= 0; i-- {
			mut = fdu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, fdu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (fdu *FileDeleteUpdate) SaveX(ctx context.Context) int {
	affected, err := fdu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (fdu *FileDeleteUpdate) Exec(ctx context.Context) error {
	_, err := fdu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (fdu *FileDeleteUpdate) ExecX(ctx context.Context) {
	if err := fdu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (fdu *FileDeleteUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   filedelete.Table,
			Columns: filedelete.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: filedelete.FieldID,
			},
		},
	}
	if ps := fdu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := fdu.mutation.HclID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: filedelete.FieldHclID,
		})
	}
	if value, ok := fdu.mutation.Path(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: filedelete.FieldPath,
		})
	}
	if value, ok := fdu.mutation.Tags(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: filedelete.FieldTags,
		})
	}
	if fdu.mutation.FileDeleteToEnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   filedelete.FileDeleteToEnvironmentTable,
			Columns: []string{filedelete.FileDeleteToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: environment.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := fdu.mutation.FileDeleteToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   filedelete.FileDeleteToEnvironmentTable,
			Columns: []string{filedelete.FileDeleteToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: environment.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, fdu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{filedelete.Label}
		} else if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return 0, err
	}
	return n, nil
}

// FileDeleteUpdateOne is the builder for updating a single FileDelete entity.
type FileDeleteUpdateOne struct {
	config
	hooks    []Hook
	mutation *FileDeleteMutation
}

// SetHclID sets the "hcl_id" field.
func (fduo *FileDeleteUpdateOne) SetHclID(s string) *FileDeleteUpdateOne {
	fduo.mutation.SetHclID(s)
	return fduo
}

// SetPath sets the "path" field.
func (fduo *FileDeleteUpdateOne) SetPath(s string) *FileDeleteUpdateOne {
	fduo.mutation.SetPath(s)
	return fduo
}

// SetTags sets the "tags" field.
func (fduo *FileDeleteUpdateOne) SetTags(m map[string]string) *FileDeleteUpdateOne {
	fduo.mutation.SetTags(m)
	return fduo
}

// SetFileDeleteToEnvironmentID sets the "FileDeleteToEnvironment" edge to the Environment entity by ID.
func (fduo *FileDeleteUpdateOne) SetFileDeleteToEnvironmentID(id int) *FileDeleteUpdateOne {
	fduo.mutation.SetFileDeleteToEnvironmentID(id)
	return fduo
}

// SetNillableFileDeleteToEnvironmentID sets the "FileDeleteToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (fduo *FileDeleteUpdateOne) SetNillableFileDeleteToEnvironmentID(id *int) *FileDeleteUpdateOne {
	if id != nil {
		fduo = fduo.SetFileDeleteToEnvironmentID(*id)
	}
	return fduo
}

// SetFileDeleteToEnvironment sets the "FileDeleteToEnvironment" edge to the Environment entity.
func (fduo *FileDeleteUpdateOne) SetFileDeleteToEnvironment(e *Environment) *FileDeleteUpdateOne {
	return fduo.SetFileDeleteToEnvironmentID(e.ID)
}

// Mutation returns the FileDeleteMutation object of the builder.
func (fduo *FileDeleteUpdateOne) Mutation() *FileDeleteMutation {
	return fduo.mutation
}

// ClearFileDeleteToEnvironment clears the "FileDeleteToEnvironment" edge to the Environment entity.
func (fduo *FileDeleteUpdateOne) ClearFileDeleteToEnvironment() *FileDeleteUpdateOne {
	fduo.mutation.ClearFileDeleteToEnvironment()
	return fduo
}

// Save executes the query and returns the updated FileDelete entity.
func (fduo *FileDeleteUpdateOne) Save(ctx context.Context) (*FileDelete, error) {
	var (
		err  error
		node *FileDelete
	)
	if len(fduo.hooks) == 0 {
		node, err = fduo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*FileDeleteMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			fduo.mutation = mutation
			node, err = fduo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(fduo.hooks) - 1; i >= 0; i-- {
			mut = fduo.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, fduo.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (fduo *FileDeleteUpdateOne) SaveX(ctx context.Context) *FileDelete {
	node, err := fduo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (fduo *FileDeleteUpdateOne) Exec(ctx context.Context) error {
	_, err := fduo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (fduo *FileDeleteUpdateOne) ExecX(ctx context.Context) {
	if err := fduo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (fduo *FileDeleteUpdateOne) sqlSave(ctx context.Context) (_node *FileDelete, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   filedelete.Table,
			Columns: filedelete.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: filedelete.FieldID,
			},
		},
	}
	id, ok := fduo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "ID", err: fmt.Errorf("missing FileDelete.ID for update")}
	}
	_spec.Node.ID.Value = id
	if ps := fduo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := fduo.mutation.HclID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: filedelete.FieldHclID,
		})
	}
	if value, ok := fduo.mutation.Path(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: filedelete.FieldPath,
		})
	}
	if value, ok := fduo.mutation.Tags(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: filedelete.FieldTags,
		})
	}
	if fduo.mutation.FileDeleteToEnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   filedelete.FileDeleteToEnvironmentTable,
			Columns: []string{filedelete.FileDeleteToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: environment.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := fduo.mutation.FileDeleteToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   filedelete.FileDeleteToEnvironmentTable,
			Columns: []string{filedelete.FileDeleteToEnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: environment.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &FileDelete{config: fduo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, fduo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{filedelete.Label}
		} else if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	return _node, nil
}
