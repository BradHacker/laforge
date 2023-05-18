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
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisioningscheduledstep"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/gen0cide/laforge/ent/validation"
	"github.com/google/uuid"
)

// AgentTaskCreate is the builder for creating a AgentTask entity.
type AgentTaskCreate struct {
	config
	mutation *AgentTaskMutation
	hooks    []Hook
}

// SetCommand sets the "command" field.
func (atc *AgentTaskCreate) SetCommand(a agenttask.Command) *AgentTaskCreate {
	atc.mutation.SetCommand(a)
	return atc
}

// SetArgs sets the "args" field.
func (atc *AgentTaskCreate) SetArgs(s string) *AgentTaskCreate {
	atc.mutation.SetArgs(s)
	return atc
}

// SetNumber sets the "number" field.
func (atc *AgentTaskCreate) SetNumber(i int) *AgentTaskCreate {
	atc.mutation.SetNumber(i)
	return atc
}

// SetOutput sets the "output" field.
func (atc *AgentTaskCreate) SetOutput(s string) *AgentTaskCreate {
	atc.mutation.SetOutput(s)
	return atc
}

// SetNillableOutput sets the "output" field if the given value is not nil.
func (atc *AgentTaskCreate) SetNillableOutput(s *string) *AgentTaskCreate {
	if s != nil {
		atc.SetOutput(*s)
	}
	return atc
}

// SetState sets the "state" field.
func (atc *AgentTaskCreate) SetState(a agenttask.State) *AgentTaskCreate {
	atc.mutation.SetState(a)
	return atc
}

// SetErrorMessage sets the "error_message" field.
func (atc *AgentTaskCreate) SetErrorMessage(s string) *AgentTaskCreate {
	atc.mutation.SetErrorMessage(s)
	return atc
}

// SetNillableErrorMessage sets the "error_message" field if the given value is not nil.
func (atc *AgentTaskCreate) SetNillableErrorMessage(s *string) *AgentTaskCreate {
	if s != nil {
		atc.SetErrorMessage(*s)
	}
	return atc
}

// SetID sets the "id" field.
func (atc *AgentTaskCreate) SetID(u uuid.UUID) *AgentTaskCreate {
	atc.mutation.SetID(u)
	return atc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (atc *AgentTaskCreate) SetNillableID(u *uuid.UUID) *AgentTaskCreate {
	if u != nil {
		atc.SetID(*u)
	}
	return atc
}

// SetProvisioningStepID sets the "ProvisioningStep" edge to the ProvisioningStep entity by ID.
func (atc *AgentTaskCreate) SetProvisioningStepID(id uuid.UUID) *AgentTaskCreate {
	atc.mutation.SetProvisioningStepID(id)
	return atc
}

// SetNillableProvisioningStepID sets the "ProvisioningStep" edge to the ProvisioningStep entity by ID if the given value is not nil.
func (atc *AgentTaskCreate) SetNillableProvisioningStepID(id *uuid.UUID) *AgentTaskCreate {
	if id != nil {
		atc = atc.SetProvisioningStepID(*id)
	}
	return atc
}

// SetProvisioningStep sets the "ProvisioningStep" edge to the ProvisioningStep entity.
func (atc *AgentTaskCreate) SetProvisioningStep(p *ProvisioningStep) *AgentTaskCreate {
	return atc.SetProvisioningStepID(p.ID)
}

// SetProvisioningScheduledStepID sets the "ProvisioningScheduledStep" edge to the ProvisioningScheduledStep entity by ID.
func (atc *AgentTaskCreate) SetProvisioningScheduledStepID(id uuid.UUID) *AgentTaskCreate {
	atc.mutation.SetProvisioningScheduledStepID(id)
	return atc
}

// SetNillableProvisioningScheduledStepID sets the "ProvisioningScheduledStep" edge to the ProvisioningScheduledStep entity by ID if the given value is not nil.
func (atc *AgentTaskCreate) SetNillableProvisioningScheduledStepID(id *uuid.UUID) *AgentTaskCreate {
	if id != nil {
		atc = atc.SetProvisioningScheduledStepID(*id)
	}
	return atc
}

// SetProvisioningScheduledStep sets the "ProvisioningScheduledStep" edge to the ProvisioningScheduledStep entity.
func (atc *AgentTaskCreate) SetProvisioningScheduledStep(p *ProvisioningScheduledStep) *AgentTaskCreate {
	return atc.SetProvisioningScheduledStepID(p.ID)
}

// SetProvisionedHostID sets the "ProvisionedHost" edge to the ProvisionedHost entity by ID.
func (atc *AgentTaskCreate) SetProvisionedHostID(id uuid.UUID) *AgentTaskCreate {
	atc.mutation.SetProvisionedHostID(id)
	return atc
}

// SetProvisionedHost sets the "ProvisionedHost" edge to the ProvisionedHost entity.
func (atc *AgentTaskCreate) SetProvisionedHost(p *ProvisionedHost) *AgentTaskCreate {
	return atc.SetProvisionedHostID(p.ID)
}

// AddAdhocPlanIDs adds the "AdhocPlans" edge to the AdhocPlan entity by IDs.
func (atc *AgentTaskCreate) AddAdhocPlanIDs(ids ...uuid.UUID) *AgentTaskCreate {
	atc.mutation.AddAdhocPlanIDs(ids...)
	return atc
}

// AddAdhocPlans adds the "AdhocPlans" edges to the AdhocPlan entity.
func (atc *AgentTaskCreate) AddAdhocPlans(a ...*AdhocPlan) *AgentTaskCreate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return atc.AddAdhocPlanIDs(ids...)
}

// SetValidationID sets the "Validation" edge to the Validation entity by ID.
func (atc *AgentTaskCreate) SetValidationID(id uuid.UUID) *AgentTaskCreate {
	atc.mutation.SetValidationID(id)
	return atc
}

// SetNillableValidationID sets the "Validation" edge to the Validation entity by ID if the given value is not nil.
func (atc *AgentTaskCreate) SetNillableValidationID(id *uuid.UUID) *AgentTaskCreate {
	if id != nil {
		atc = atc.SetValidationID(*id)
	}
	return atc
}

// SetValidation sets the "Validation" edge to the Validation entity.
func (atc *AgentTaskCreate) SetValidation(v *Validation) *AgentTaskCreate {
	return atc.SetValidationID(v.ID)
}

// Mutation returns the AgentTaskMutation object of the builder.
func (atc *AgentTaskCreate) Mutation() *AgentTaskMutation {
	return atc.mutation
}

// Save creates the AgentTask in the database.
func (atc *AgentTaskCreate) Save(ctx context.Context) (*AgentTask, error) {
	atc.defaults()
	return withHooks(ctx, atc.sqlSave, atc.mutation, atc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (atc *AgentTaskCreate) SaveX(ctx context.Context) *AgentTask {
	v, err := atc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (atc *AgentTaskCreate) Exec(ctx context.Context) error {
	_, err := atc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atc *AgentTaskCreate) ExecX(ctx context.Context) {
	if err := atc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (atc *AgentTaskCreate) defaults() {
	if _, ok := atc.mutation.Output(); !ok {
		v := agenttask.DefaultOutput
		atc.mutation.SetOutput(v)
	}
	if _, ok := atc.mutation.ErrorMessage(); !ok {
		v := agenttask.DefaultErrorMessage
		atc.mutation.SetErrorMessage(v)
	}
	if _, ok := atc.mutation.ID(); !ok {
		v := agenttask.DefaultID()
		atc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (atc *AgentTaskCreate) check() error {
	if _, ok := atc.mutation.Command(); !ok {
		return &ValidationError{Name: "command", err: errors.New(`ent: missing required field "AgentTask.command"`)}
	}
	if v, ok := atc.mutation.Command(); ok {
		if err := agenttask.CommandValidator(v); err != nil {
			return &ValidationError{Name: "command", err: fmt.Errorf(`ent: validator failed for field "AgentTask.command": %w`, err)}
		}
	}
	if _, ok := atc.mutation.Args(); !ok {
		return &ValidationError{Name: "args", err: errors.New(`ent: missing required field "AgentTask.args"`)}
	}
	if _, ok := atc.mutation.Number(); !ok {
		return &ValidationError{Name: "number", err: errors.New(`ent: missing required field "AgentTask.number"`)}
	}
	if _, ok := atc.mutation.Output(); !ok {
		return &ValidationError{Name: "output", err: errors.New(`ent: missing required field "AgentTask.output"`)}
	}
	if _, ok := atc.mutation.State(); !ok {
		return &ValidationError{Name: "state", err: errors.New(`ent: missing required field "AgentTask.state"`)}
	}
	if v, ok := atc.mutation.State(); ok {
		if err := agenttask.StateValidator(v); err != nil {
			return &ValidationError{Name: "state", err: fmt.Errorf(`ent: validator failed for field "AgentTask.state": %w`, err)}
		}
	}
	if _, ok := atc.mutation.ErrorMessage(); !ok {
		return &ValidationError{Name: "error_message", err: errors.New(`ent: missing required field "AgentTask.error_message"`)}
	}
	if _, ok := atc.mutation.ProvisionedHostID(); !ok {
		return &ValidationError{Name: "ProvisionedHost", err: errors.New(`ent: missing required edge "AgentTask.ProvisionedHost"`)}
	}
	return nil
}

func (atc *AgentTaskCreate) sqlSave(ctx context.Context) (*AgentTask, error) {
	if err := atc.check(); err != nil {
		return nil, err
	}
	_node, _spec := atc.createSpec()
	if err := sqlgraph.CreateNode(ctx, atc.driver, _spec); err != nil {
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
	atc.mutation.id = &_node.ID
	atc.mutation.done = true
	return _node, nil
}

func (atc *AgentTaskCreate) createSpec() (*AgentTask, *sqlgraph.CreateSpec) {
	var (
		_node = &AgentTask{config: atc.config}
		_spec = sqlgraph.NewCreateSpec(agenttask.Table, sqlgraph.NewFieldSpec(agenttask.FieldID, field.TypeUUID))
	)
	if id, ok := atc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := atc.mutation.Command(); ok {
		_spec.SetField(agenttask.FieldCommand, field.TypeEnum, value)
		_node.Command = value
	}
	if value, ok := atc.mutation.Args(); ok {
		_spec.SetField(agenttask.FieldArgs, field.TypeString, value)
		_node.Args = value
	}
	if value, ok := atc.mutation.Number(); ok {
		_spec.SetField(agenttask.FieldNumber, field.TypeInt, value)
		_node.Number = value
	}
	if value, ok := atc.mutation.Output(); ok {
		_spec.SetField(agenttask.FieldOutput, field.TypeString, value)
		_node.Output = value
	}
	if value, ok := atc.mutation.State(); ok {
		_spec.SetField(agenttask.FieldState, field.TypeEnum, value)
		_node.State = value
	}
	if value, ok := atc.mutation.ErrorMessage(); ok {
		_spec.SetField(agenttask.FieldErrorMessage, field.TypeString, value)
		_node.ErrorMessage = value
	}
	if nodes := atc.mutation.ProvisioningStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.ProvisioningStepTable,
			Columns: []string{agenttask.ProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(provisioningstep.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_task_provisioning_step = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := atc.mutation.ProvisioningScheduledStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.ProvisioningScheduledStepTable,
			Columns: []string{agenttask.ProvisioningScheduledStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(provisioningscheduledstep.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_task_provisioning_scheduled_step = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := atc.mutation.ProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.ProvisionedHostTable,
			Columns: []string{agenttask.ProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(provisionedhost.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_task_provisioned_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := atc.mutation.AdhocPlansIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AdhocPlansTable,
			Columns: []string{agenttask.AdhocPlansColumn},
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
	if nodes := atc.mutation.ValidationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.ValidationTable,
			Columns: []string{agenttask.ValidationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(validation.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_task_validation = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AgentTaskCreateBulk is the builder for creating many AgentTask entities in bulk.
type AgentTaskCreateBulk struct {
	config
	builders []*AgentTaskCreate
}

// Save creates the AgentTask entities in the database.
func (atcb *AgentTaskCreateBulk) Save(ctx context.Context) ([]*AgentTask, error) {
	specs := make([]*sqlgraph.CreateSpec, len(atcb.builders))
	nodes := make([]*AgentTask, len(atcb.builders))
	mutators := make([]Mutator, len(atcb.builders))
	for i := range atcb.builders {
		func(i int, root context.Context) {
			builder := atcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AgentTaskMutation)
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
					_, err = mutators[i+1].Mutate(root, atcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, atcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, atcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (atcb *AgentTaskCreateBulk) SaveX(ctx context.Context) []*AgentTask {
	v, err := atcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (atcb *AgentTaskCreateBulk) Exec(ctx context.Context) error {
	_, err := atcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atcb *AgentTaskCreateBulk) ExecX(ctx context.Context) {
	if err := atcb.Exec(ctx); err != nil {
		panic(err)
	}
}
