// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/ginfilemiddleware"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisioningstep"
)

// GinFileMiddlewareUpdate is the builder for updating GinFileMiddleware entities.
type GinFileMiddlewareUpdate struct {
	config
	hooks    []Hook
	mutation *GinFileMiddlewareMutation
}

// Where adds a new predicate for the GinFileMiddlewareUpdate builder.
func (gfmu *GinFileMiddlewareUpdate) Where(ps ...predicate.GinFileMiddleware) *GinFileMiddlewareUpdate {
	gfmu.mutation.predicates = append(gfmu.mutation.predicates, ps...)
	return gfmu
}

// SetURLID sets the "url_id" field.
func (gfmu *GinFileMiddlewareUpdate) SetURLID(s string) *GinFileMiddlewareUpdate {
	gfmu.mutation.SetURLID(s)
	return gfmu
}

// SetFilePath sets the "file_path" field.
func (gfmu *GinFileMiddlewareUpdate) SetFilePath(s string) *GinFileMiddlewareUpdate {
	gfmu.mutation.SetFilePath(s)
	return gfmu
}

// SetAccessed sets the "accessed" field.
func (gfmu *GinFileMiddlewareUpdate) SetAccessed(b bool) *GinFileMiddlewareUpdate {
	gfmu.mutation.SetAccessed(b)
	return gfmu
}

// SetNillableAccessed sets the "accessed" field if the given value is not nil.
func (gfmu *GinFileMiddlewareUpdate) SetNillableAccessed(b *bool) *GinFileMiddlewareUpdate {
	if b != nil {
		gfmu.SetAccessed(*b)
	}
	return gfmu
}

// SetGinFileMiddlewareToProvisionedHostID sets the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity by ID.
func (gfmu *GinFileMiddlewareUpdate) SetGinFileMiddlewareToProvisionedHostID(id int) *GinFileMiddlewareUpdate {
	gfmu.mutation.SetGinFileMiddlewareToProvisionedHostID(id)
	return gfmu
}

// SetNillableGinFileMiddlewareToProvisionedHostID sets the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity by ID if the given value is not nil.
func (gfmu *GinFileMiddlewareUpdate) SetNillableGinFileMiddlewareToProvisionedHostID(id *int) *GinFileMiddlewareUpdate {
	if id != nil {
		gfmu = gfmu.SetGinFileMiddlewareToProvisionedHostID(*id)
	}
	return gfmu
}

// SetGinFileMiddlewareToProvisionedHost sets the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity.
func (gfmu *GinFileMiddlewareUpdate) SetGinFileMiddlewareToProvisionedHost(p *ProvisionedHost) *GinFileMiddlewareUpdate {
	return gfmu.SetGinFileMiddlewareToProvisionedHostID(p.ID)
}

// SetGinFileMiddlewareToProvisioningStepID sets the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity by ID.
func (gfmu *GinFileMiddlewareUpdate) SetGinFileMiddlewareToProvisioningStepID(id int) *GinFileMiddlewareUpdate {
	gfmu.mutation.SetGinFileMiddlewareToProvisioningStepID(id)
	return gfmu
}

// SetNillableGinFileMiddlewareToProvisioningStepID sets the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity by ID if the given value is not nil.
func (gfmu *GinFileMiddlewareUpdate) SetNillableGinFileMiddlewareToProvisioningStepID(id *int) *GinFileMiddlewareUpdate {
	if id != nil {
		gfmu = gfmu.SetGinFileMiddlewareToProvisioningStepID(*id)
	}
	return gfmu
}

// SetGinFileMiddlewareToProvisioningStep sets the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity.
func (gfmu *GinFileMiddlewareUpdate) SetGinFileMiddlewareToProvisioningStep(p *ProvisioningStep) *GinFileMiddlewareUpdate {
	return gfmu.SetGinFileMiddlewareToProvisioningStepID(p.ID)
}

// Mutation returns the GinFileMiddlewareMutation object of the builder.
func (gfmu *GinFileMiddlewareUpdate) Mutation() *GinFileMiddlewareMutation {
	return gfmu.mutation
}

// ClearGinFileMiddlewareToProvisionedHost clears the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity.
func (gfmu *GinFileMiddlewareUpdate) ClearGinFileMiddlewareToProvisionedHost() *GinFileMiddlewareUpdate {
	gfmu.mutation.ClearGinFileMiddlewareToProvisionedHost()
	return gfmu
}

// ClearGinFileMiddlewareToProvisioningStep clears the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity.
func (gfmu *GinFileMiddlewareUpdate) ClearGinFileMiddlewareToProvisioningStep() *GinFileMiddlewareUpdate {
	gfmu.mutation.ClearGinFileMiddlewareToProvisioningStep()
	return gfmu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (gfmu *GinFileMiddlewareUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(gfmu.hooks) == 0 {
		affected, err = gfmu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*GinFileMiddlewareMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			gfmu.mutation = mutation
			affected, err = gfmu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(gfmu.hooks) - 1; i >= 0; i-- {
			mut = gfmu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, gfmu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (gfmu *GinFileMiddlewareUpdate) SaveX(ctx context.Context) int {
	affected, err := gfmu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (gfmu *GinFileMiddlewareUpdate) Exec(ctx context.Context) error {
	_, err := gfmu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfmu *GinFileMiddlewareUpdate) ExecX(ctx context.Context) {
	if err := gfmu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (gfmu *GinFileMiddlewareUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   ginfilemiddleware.Table,
			Columns: ginfilemiddleware.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: ginfilemiddleware.FieldID,
			},
		},
	}
	if ps := gfmu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := gfmu.mutation.URLID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ginfilemiddleware.FieldURLID,
		})
	}
	if value, ok := gfmu.mutation.FilePath(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ginfilemiddleware.FieldFilePath,
		})
	}
	if value, ok := gfmu.mutation.Accessed(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: ginfilemiddleware.FieldAccessed,
		})
	}
	if gfmu.mutation.GinFileMiddlewareToProvisionedHostCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisionedHostTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisionedhost.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := gfmu.mutation.GinFileMiddlewareToProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisionedHostTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisionedhost.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if gfmu.mutation.GinFileMiddlewareToProvisioningStepCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisioningStepTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisioningstep.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := gfmu.mutation.GinFileMiddlewareToProvisioningStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisioningStepTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisioningstep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, gfmu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{ginfilemiddleware.Label}
		} else if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return 0, err
	}
	return n, nil
}

// GinFileMiddlewareUpdateOne is the builder for updating a single GinFileMiddleware entity.
type GinFileMiddlewareUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *GinFileMiddlewareMutation
}

// SetURLID sets the "url_id" field.
func (gfmuo *GinFileMiddlewareUpdateOne) SetURLID(s string) *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.SetURLID(s)
	return gfmuo
}

// SetFilePath sets the "file_path" field.
func (gfmuo *GinFileMiddlewareUpdateOne) SetFilePath(s string) *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.SetFilePath(s)
	return gfmuo
}

// SetAccessed sets the "accessed" field.
func (gfmuo *GinFileMiddlewareUpdateOne) SetAccessed(b bool) *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.SetAccessed(b)
	return gfmuo
}

// SetNillableAccessed sets the "accessed" field if the given value is not nil.
func (gfmuo *GinFileMiddlewareUpdateOne) SetNillableAccessed(b *bool) *GinFileMiddlewareUpdateOne {
	if b != nil {
		gfmuo.SetAccessed(*b)
	}
	return gfmuo
}

// SetGinFileMiddlewareToProvisionedHostID sets the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity by ID.
func (gfmuo *GinFileMiddlewareUpdateOne) SetGinFileMiddlewareToProvisionedHostID(id int) *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.SetGinFileMiddlewareToProvisionedHostID(id)
	return gfmuo
}

// SetNillableGinFileMiddlewareToProvisionedHostID sets the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity by ID if the given value is not nil.
func (gfmuo *GinFileMiddlewareUpdateOne) SetNillableGinFileMiddlewareToProvisionedHostID(id *int) *GinFileMiddlewareUpdateOne {
	if id != nil {
		gfmuo = gfmuo.SetGinFileMiddlewareToProvisionedHostID(*id)
	}
	return gfmuo
}

// SetGinFileMiddlewareToProvisionedHost sets the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity.
func (gfmuo *GinFileMiddlewareUpdateOne) SetGinFileMiddlewareToProvisionedHost(p *ProvisionedHost) *GinFileMiddlewareUpdateOne {
	return gfmuo.SetGinFileMiddlewareToProvisionedHostID(p.ID)
}

// SetGinFileMiddlewareToProvisioningStepID sets the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity by ID.
func (gfmuo *GinFileMiddlewareUpdateOne) SetGinFileMiddlewareToProvisioningStepID(id int) *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.SetGinFileMiddlewareToProvisioningStepID(id)
	return gfmuo
}

// SetNillableGinFileMiddlewareToProvisioningStepID sets the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity by ID if the given value is not nil.
func (gfmuo *GinFileMiddlewareUpdateOne) SetNillableGinFileMiddlewareToProvisioningStepID(id *int) *GinFileMiddlewareUpdateOne {
	if id != nil {
		gfmuo = gfmuo.SetGinFileMiddlewareToProvisioningStepID(*id)
	}
	return gfmuo
}

// SetGinFileMiddlewareToProvisioningStep sets the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity.
func (gfmuo *GinFileMiddlewareUpdateOne) SetGinFileMiddlewareToProvisioningStep(p *ProvisioningStep) *GinFileMiddlewareUpdateOne {
	return gfmuo.SetGinFileMiddlewareToProvisioningStepID(p.ID)
}

// Mutation returns the GinFileMiddlewareMutation object of the builder.
func (gfmuo *GinFileMiddlewareUpdateOne) Mutation() *GinFileMiddlewareMutation {
	return gfmuo.mutation
}

// ClearGinFileMiddlewareToProvisionedHost clears the "GinFileMiddlewareToProvisionedHost" edge to the ProvisionedHost entity.
func (gfmuo *GinFileMiddlewareUpdateOne) ClearGinFileMiddlewareToProvisionedHost() *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.ClearGinFileMiddlewareToProvisionedHost()
	return gfmuo
}

// ClearGinFileMiddlewareToProvisioningStep clears the "GinFileMiddlewareToProvisioningStep" edge to the ProvisioningStep entity.
func (gfmuo *GinFileMiddlewareUpdateOne) ClearGinFileMiddlewareToProvisioningStep() *GinFileMiddlewareUpdateOne {
	gfmuo.mutation.ClearGinFileMiddlewareToProvisioningStep()
	return gfmuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (gfmuo *GinFileMiddlewareUpdateOne) Select(field string, fields ...string) *GinFileMiddlewareUpdateOne {
	gfmuo.fields = append([]string{field}, fields...)
	return gfmuo
}

// Save executes the query and returns the updated GinFileMiddleware entity.
func (gfmuo *GinFileMiddlewareUpdateOne) Save(ctx context.Context) (*GinFileMiddleware, error) {
	var (
		err  error
		node *GinFileMiddleware
	)
	if len(gfmuo.hooks) == 0 {
		node, err = gfmuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*GinFileMiddlewareMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			gfmuo.mutation = mutation
			node, err = gfmuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(gfmuo.hooks) - 1; i >= 0; i-- {
			mut = gfmuo.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, gfmuo.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (gfmuo *GinFileMiddlewareUpdateOne) SaveX(ctx context.Context) *GinFileMiddleware {
	node, err := gfmuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (gfmuo *GinFileMiddlewareUpdateOne) Exec(ctx context.Context) error {
	_, err := gfmuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (gfmuo *GinFileMiddlewareUpdateOne) ExecX(ctx context.Context) {
	if err := gfmuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (gfmuo *GinFileMiddlewareUpdateOne) sqlSave(ctx context.Context) (_node *GinFileMiddleware, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   ginfilemiddleware.Table,
			Columns: ginfilemiddleware.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: ginfilemiddleware.FieldID,
			},
		},
	}
	id, ok := gfmuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "ID", err: fmt.Errorf("missing GinFileMiddleware.ID for update")}
	}
	_spec.Node.ID.Value = id
	if fields := gfmuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, ginfilemiddleware.FieldID)
		for _, f := range fields {
			if !ginfilemiddleware.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != ginfilemiddleware.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := gfmuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := gfmuo.mutation.URLID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ginfilemiddleware.FieldURLID,
		})
	}
	if value, ok := gfmuo.mutation.FilePath(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ginfilemiddleware.FieldFilePath,
		})
	}
	if value, ok := gfmuo.mutation.Accessed(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: ginfilemiddleware.FieldAccessed,
		})
	}
	if gfmuo.mutation.GinFileMiddlewareToProvisionedHostCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisionedHostTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisionedhost.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := gfmuo.mutation.GinFileMiddlewareToProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisionedHostTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisionedhost.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if gfmuo.mutation.GinFileMiddlewareToProvisioningStepCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisioningStepTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisioningstep.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := gfmuo.mutation.GinFileMiddlewareToProvisioningStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   ginfilemiddleware.GinFileMiddlewareToProvisioningStepTable,
			Columns: []string{ginfilemiddleware.GinFileMiddlewareToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: provisioningstep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &GinFileMiddleware{config: gfmuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, gfmuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{ginfilemiddleware.Label}
		} else if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	return _node, nil
}
