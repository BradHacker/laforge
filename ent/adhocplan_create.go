// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/adhocplan"
	"github.com/gen0cide/laforge/ent/agenttask"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/google/uuid"
)

// AdhocPlanCreate is the builder for creating a AdhocPlan entity.
type AdhocPlanCreate struct {
	config
	mutation *AdhocPlanMutation
	hooks    []Hook
}

// SetID sets the "id" field.
func (apc *AdhocPlanCreate) SetID(u uuid.UUID) *AdhocPlanCreate {
	apc.mutation.SetID(u)
	return apc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (apc *AdhocPlanCreate) SetNillableID(u *uuid.UUID) *AdhocPlanCreate {
	if u != nil {
		apc.SetID(*u)
	}
	return apc
}

// AddPrevAdhocPlanIDs adds the "PrevAdhocPlans" edge to the AdhocPlan entity by IDs.
func (apc *AdhocPlanCreate) AddPrevAdhocPlanIDs(ids ...uuid.UUID) *AdhocPlanCreate {
	apc.mutation.AddPrevAdhocPlanIDs(ids...)
	return apc
}

// AddPrevAdhocPlans adds the "PrevAdhocPlans" edges to the AdhocPlan entity.
func (apc *AdhocPlanCreate) AddPrevAdhocPlans(a ...*AdhocPlan) *AdhocPlanCreate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return apc.AddPrevAdhocPlanIDs(ids...)
}

// AddNextAdhocPlanIDs adds the "NextAdhocPlans" edge to the AdhocPlan entity by IDs.
func (apc *AdhocPlanCreate) AddNextAdhocPlanIDs(ids ...uuid.UUID) *AdhocPlanCreate {
	apc.mutation.AddNextAdhocPlanIDs(ids...)
	return apc
}

// AddNextAdhocPlans adds the "NextAdhocPlans" edges to the AdhocPlan entity.
func (apc *AdhocPlanCreate) AddNextAdhocPlans(a ...*AdhocPlan) *AdhocPlanCreate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return apc.AddNextAdhocPlanIDs(ids...)
}

// SetBuildID sets the "Build" edge to the Build entity by ID.
func (apc *AdhocPlanCreate) SetBuildID(id uuid.UUID) *AdhocPlanCreate {
	apc.mutation.SetBuildID(id)
	return apc
}

// SetBuild sets the "Build" edge to the Build entity.
func (apc *AdhocPlanCreate) SetBuild(b *Build) *AdhocPlanCreate {
	return apc.SetBuildID(b.ID)
}

// SetStatusID sets the "Status" edge to the Status entity by ID.
func (apc *AdhocPlanCreate) SetStatusID(id uuid.UUID) *AdhocPlanCreate {
	apc.mutation.SetStatusID(id)
	return apc
}

// SetStatus sets the "Status" edge to the Status entity.
func (apc *AdhocPlanCreate) SetStatus(s *Status) *AdhocPlanCreate {
	return apc.SetStatusID(s.ID)
}

// SetAgentTaskID sets the "AgentTask" edge to the AgentTask entity by ID.
func (apc *AdhocPlanCreate) SetAgentTaskID(id uuid.UUID) *AdhocPlanCreate {
	apc.mutation.SetAgentTaskID(id)
	return apc
}

// SetAgentTask sets the "AgentTask" edge to the AgentTask entity.
func (apc *AdhocPlanCreate) SetAgentTask(a *AgentTask) *AdhocPlanCreate {
	return apc.SetAgentTaskID(a.ID)
}

// Mutation returns the AdhocPlanMutation object of the builder.
func (apc *AdhocPlanCreate) Mutation() *AdhocPlanMutation {
	return apc.mutation
}

// Save creates the AdhocPlan in the database.
func (apc *AdhocPlanCreate) Save(ctx context.Context) (*AdhocPlan, error) {
	apc.defaults()
	return withHooks(ctx, apc.sqlSave, apc.mutation, apc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (apc *AdhocPlanCreate) SaveX(ctx context.Context) *AdhocPlan {
	v, err := apc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (apc *AdhocPlanCreate) Exec(ctx context.Context) error {
	_, err := apc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (apc *AdhocPlanCreate) ExecX(ctx context.Context) {
	if err := apc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (apc *AdhocPlanCreate) defaults() {
	if _, ok := apc.mutation.ID(); !ok {
		v := adhocplan.DefaultID()
		apc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (apc *AdhocPlanCreate) check() error {
	if _, ok := apc.mutation.BuildID(); !ok {
		return &ValidationError{Name: "Build", err: errors.New(`ent: missing required edge "AdhocPlan.Build"`)}
	}
	if _, ok := apc.mutation.StatusID(); !ok {
		return &ValidationError{Name: "Status", err: errors.New(`ent: missing required edge "AdhocPlan.Status"`)}
	}
	if _, ok := apc.mutation.AgentTaskID(); !ok {
		return &ValidationError{Name: "AgentTask", err: errors.New(`ent: missing required edge "AdhocPlan.AgentTask"`)}
	}
	return nil
}

func (apc *AdhocPlanCreate) sqlSave(ctx context.Context) (*AdhocPlan, error) {
	if err := apc.check(); err != nil {
		return nil, err
	}
	_node, _spec := apc.createSpec()
	if err := sqlgraph.CreateNode(ctx, apc.driver, _spec); err != nil {
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
	apc.mutation.id = &_node.ID
	apc.mutation.done = true
	return _node, nil
}

func (apc *AdhocPlanCreate) createSpec() (*AdhocPlan, *sqlgraph.CreateSpec) {
	var (
		_node = &AdhocPlan{config: apc.config}
		_spec = sqlgraph.NewCreateSpec(adhocplan.Table, sqlgraph.NewFieldSpec(adhocplan.FieldID, field.TypeUUID))
	)
	if id, ok := apc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if nodes := apc.mutation.PrevAdhocPlansIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   adhocplan.PrevAdhocPlansTable,
			Columns: adhocplan.PrevAdhocPlansPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(adhocplan.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := apc.mutation.NextAdhocPlansIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   adhocplan.NextAdhocPlansTable,
			Columns: adhocplan.NextAdhocPlansPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(adhocplan.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := apc.mutation.BuildIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   adhocplan.BuildTable,
			Columns: []string{adhocplan.BuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(build.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.adhoc_plan_build = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := apc.mutation.StatusIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   adhocplan.StatusTable,
			Columns: []string{adhocplan.StatusColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(status.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := apc.mutation.AgentTaskIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   adhocplan.AgentTaskTable,
			Columns: []string{adhocplan.AgentTaskColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(agenttask.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.adhoc_plan_agent_task = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AdhocPlanCreateBulk is the builder for creating many AdhocPlan entities in bulk.
type AdhocPlanCreateBulk struct {
	config
	builders []*AdhocPlanCreate
}

// Save creates the AdhocPlan entities in the database.
func (apcb *AdhocPlanCreateBulk) Save(ctx context.Context) ([]*AdhocPlan, error) {
	specs := make([]*sqlgraph.CreateSpec, len(apcb.builders))
	nodes := make([]*AdhocPlan, len(apcb.builders))
	mutators := make([]Mutator, len(apcb.builders))
	for i := range apcb.builders {
		func(i int, root context.Context) {
			builder := apcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AdhocPlanMutation)
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
					_, err = mutators[i+1].Mutate(root, apcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, apcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, apcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (apcb *AdhocPlanCreateBulk) SaveX(ctx context.Context) []*AdhocPlan {
	v, err := apcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (apcb *AdhocPlanCreateBulk) Exec(ctx context.Context) error {
	_, err := apcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (apcb *AdhocPlanCreateBulk) ExecX(ctx context.Context) {
	if err := apcb.Exec(ctx); err != nil {
		panic(err)
	}
}
