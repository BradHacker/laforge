// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/adhocplan"
	"github.com/gen0cide/laforge/ent/agenttask"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionedschedulestep"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/google/uuid"
)

// AgentTaskUpdate is the builder for updating AgentTask entities.
type AgentTaskUpdate struct {
	config
	hooks    []Hook
	mutation *AgentTaskMutation
}

// Where appends a list predicates to the AgentTaskUpdate builder.
func (atu *AgentTaskUpdate) Where(ps ...predicate.AgentTask) *AgentTaskUpdate {
	atu.mutation.Where(ps...)
	return atu
}

// SetCommand sets the "command" field.
func (atu *AgentTaskUpdate) SetCommand(a agenttask.Command) *AgentTaskUpdate {
	atu.mutation.SetCommand(a)
	return atu
}

// SetArgs sets the "args" field.
func (atu *AgentTaskUpdate) SetArgs(s string) *AgentTaskUpdate {
	atu.mutation.SetArgs(s)
	return atu
}

// SetNumber sets the "number" field.
func (atu *AgentTaskUpdate) SetNumber(i int) *AgentTaskUpdate {
	atu.mutation.ResetNumber()
	atu.mutation.SetNumber(i)
	return atu
}

// AddNumber adds i to the "number" field.
func (atu *AgentTaskUpdate) AddNumber(i int) *AgentTaskUpdate {
	atu.mutation.AddNumber(i)
	return atu
}

// SetOutput sets the "output" field.
func (atu *AgentTaskUpdate) SetOutput(s string) *AgentTaskUpdate {
	atu.mutation.SetOutput(s)
	return atu
}

// SetNillableOutput sets the "output" field if the given value is not nil.
func (atu *AgentTaskUpdate) SetNillableOutput(s *string) *AgentTaskUpdate {
	if s != nil {
		atu.SetOutput(*s)
	}
	return atu
}

// SetState sets the "state" field.
func (atu *AgentTaskUpdate) SetState(a agenttask.State) *AgentTaskUpdate {
	atu.mutation.SetState(a)
	return atu
}

// SetErrorMessage sets the "error_message" field.
func (atu *AgentTaskUpdate) SetErrorMessage(s string) *AgentTaskUpdate {
	atu.mutation.SetErrorMessage(s)
	return atu
}

// SetNillableErrorMessage sets the "error_message" field if the given value is not nil.
func (atu *AgentTaskUpdate) SetNillableErrorMessage(s *string) *AgentTaskUpdate {
	if s != nil {
		atu.SetErrorMessage(*s)
	}
	return atu
}

// SetAgentTaskToProvisioningStepID sets the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity by ID.
func (atu *AgentTaskUpdate) SetAgentTaskToProvisioningStepID(id uuid.UUID) *AgentTaskUpdate {
	atu.mutation.SetAgentTaskToProvisioningStepID(id)
	return atu
}

// SetNillableAgentTaskToProvisioningStepID sets the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity by ID if the given value is not nil.
func (atu *AgentTaskUpdate) SetNillableAgentTaskToProvisioningStepID(id *uuid.UUID) *AgentTaskUpdate {
	if id != nil {
		atu = atu.SetAgentTaskToProvisioningStepID(*id)
	}
	return atu
}

// SetAgentTaskToProvisioningStep sets the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity.
func (atu *AgentTaskUpdate) SetAgentTaskToProvisioningStep(p *ProvisioningStep) *AgentTaskUpdate {
	return atu.SetAgentTaskToProvisioningStepID(p.ID)
}

// SetAgentTaskToProvisionedHostID sets the "AgentTaskToProvisionedHost" edge to the ProvisionedHost entity by ID.
func (atu *AgentTaskUpdate) SetAgentTaskToProvisionedHostID(id uuid.UUID) *AgentTaskUpdate {
	atu.mutation.SetAgentTaskToProvisionedHostID(id)
	return atu
}

// SetAgentTaskToProvisionedHost sets the "AgentTaskToProvisionedHost" edge to the ProvisionedHost entity.
func (atu *AgentTaskUpdate) SetAgentTaskToProvisionedHost(p *ProvisionedHost) *AgentTaskUpdate {
	return atu.SetAgentTaskToProvisionedHostID(p.ID)
}

// SetAgentTaskToProvisionedScheduleStepID sets the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity by ID.
func (atu *AgentTaskUpdate) SetAgentTaskToProvisionedScheduleStepID(id uuid.UUID) *AgentTaskUpdate {
	atu.mutation.SetAgentTaskToProvisionedScheduleStepID(id)
	return atu
}

// SetNillableAgentTaskToProvisionedScheduleStepID sets the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity by ID if the given value is not nil.
func (atu *AgentTaskUpdate) SetNillableAgentTaskToProvisionedScheduleStepID(id *uuid.UUID) *AgentTaskUpdate {
	if id != nil {
		atu = atu.SetAgentTaskToProvisionedScheduleStepID(*id)
	}
	return atu
}

// SetAgentTaskToProvisionedScheduleStep sets the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity.
func (atu *AgentTaskUpdate) SetAgentTaskToProvisionedScheduleStep(p *ProvisionedScheduleStep) *AgentTaskUpdate {
	return atu.SetAgentTaskToProvisionedScheduleStepID(p.ID)
}

// AddAgentTaskToAdhocPlanIDs adds the "AgentTaskToAdhocPlan" edge to the AdhocPlan entity by IDs.
func (atu *AgentTaskUpdate) AddAgentTaskToAdhocPlanIDs(ids ...uuid.UUID) *AgentTaskUpdate {
	atu.mutation.AddAgentTaskToAdhocPlanIDs(ids...)
	return atu
}

// AddAgentTaskToAdhocPlan adds the "AgentTaskToAdhocPlan" edges to the AdhocPlan entity.
func (atu *AgentTaskUpdate) AddAgentTaskToAdhocPlan(a ...*AdhocPlan) *AgentTaskUpdate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return atu.AddAgentTaskToAdhocPlanIDs(ids...)
}

// Mutation returns the AgentTaskMutation object of the builder.
func (atu *AgentTaskUpdate) Mutation() *AgentTaskMutation {
	return atu.mutation
}

// ClearAgentTaskToProvisioningStep clears the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity.
func (atu *AgentTaskUpdate) ClearAgentTaskToProvisioningStep() *AgentTaskUpdate {
	atu.mutation.ClearAgentTaskToProvisioningStep()
	return atu
}

// ClearAgentTaskToProvisionedHost clears the "AgentTaskToProvisionedHost" edge to the ProvisionedHost entity.
func (atu *AgentTaskUpdate) ClearAgentTaskToProvisionedHost() *AgentTaskUpdate {
	atu.mutation.ClearAgentTaskToProvisionedHost()
	return atu
}

// ClearAgentTaskToProvisionedScheduleStep clears the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity.
func (atu *AgentTaskUpdate) ClearAgentTaskToProvisionedScheduleStep() *AgentTaskUpdate {
	atu.mutation.ClearAgentTaskToProvisionedScheduleStep()
	return atu
}

// ClearAgentTaskToAdhocPlan clears all "AgentTaskToAdhocPlan" edges to the AdhocPlan entity.
func (atu *AgentTaskUpdate) ClearAgentTaskToAdhocPlan() *AgentTaskUpdate {
	atu.mutation.ClearAgentTaskToAdhocPlan()
	return atu
}

// RemoveAgentTaskToAdhocPlanIDs removes the "AgentTaskToAdhocPlan" edge to AdhocPlan entities by IDs.
func (atu *AgentTaskUpdate) RemoveAgentTaskToAdhocPlanIDs(ids ...uuid.UUID) *AgentTaskUpdate {
	atu.mutation.RemoveAgentTaskToAdhocPlanIDs(ids...)
	return atu
}

// RemoveAgentTaskToAdhocPlan removes "AgentTaskToAdhocPlan" edges to AdhocPlan entities.
func (atu *AgentTaskUpdate) RemoveAgentTaskToAdhocPlan(a ...*AdhocPlan) *AgentTaskUpdate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return atu.RemoveAgentTaskToAdhocPlanIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (atu *AgentTaskUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(atu.hooks) == 0 {
		if err = atu.check(); err != nil {
			return 0, err
		}
		affected, err = atu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AgentTaskMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = atu.check(); err != nil {
				return 0, err
			}
			atu.mutation = mutation
			affected, err = atu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(atu.hooks) - 1; i >= 0; i-- {
			if atu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = atu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, atu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (atu *AgentTaskUpdate) SaveX(ctx context.Context) int {
	affected, err := atu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (atu *AgentTaskUpdate) Exec(ctx context.Context) error {
	_, err := atu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atu *AgentTaskUpdate) ExecX(ctx context.Context) {
	if err := atu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (atu *AgentTaskUpdate) check() error {
	if v, ok := atu.mutation.Command(); ok {
		if err := agenttask.CommandValidator(v); err != nil {
			return &ValidationError{Name: "command", err: fmt.Errorf(`ent: validator failed for field "AgentTask.command": %w`, err)}
		}
	}
	if v, ok := atu.mutation.State(); ok {
		if err := agenttask.StateValidator(v); err != nil {
			return &ValidationError{Name: "state", err: fmt.Errorf(`ent: validator failed for field "AgentTask.state": %w`, err)}
		}
	}
	if _, ok := atu.mutation.AgentTaskToProvisionedHostID(); atu.mutation.AgentTaskToProvisionedHostCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "AgentTask.AgentTaskToProvisionedHost"`)
	}
	return nil
}

func (atu *AgentTaskUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   agenttask.Table,
			Columns: agenttask.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: agenttask.FieldID,
			},
		},
	}
	if ps := atu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := atu.mutation.Command(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: agenttask.FieldCommand,
		})
	}
	if value, ok := atu.mutation.Args(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agenttask.FieldArgs,
		})
	}
	if value, ok := atu.mutation.Number(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: agenttask.FieldNumber,
		})
	}
	if value, ok := atu.mutation.AddedNumber(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: agenttask.FieldNumber,
		})
	}
	if value, ok := atu.mutation.Output(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agenttask.FieldOutput,
		})
	}
	if value, ok := atu.mutation.State(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: agenttask.FieldState,
		})
	}
	if value, ok := atu.mutation.ErrorMessage(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agenttask.FieldErrorMessage,
		})
	}
	if atu.mutation.AgentTaskToProvisioningStepCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisioningStepTable,
			Columns: []string{agenttask.AgentTaskToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisioningstep.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.AgentTaskToProvisioningStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisioningStepTable,
			Columns: []string{agenttask.AgentTaskToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisioningstep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atu.mutation.AgentTaskToProvisionedHostCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedHostTable,
			Columns: []string{agenttask.AgentTaskToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedhost.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.AgentTaskToProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedHostTable,
			Columns: []string{agenttask.AgentTaskToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedhost.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atu.mutation.AgentTaskToProvisionedScheduleStepCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedScheduleStepTable,
			Columns: []string{agenttask.AgentTaskToProvisionedScheduleStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedschedulestep.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.AgentTaskToProvisionedScheduleStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedScheduleStepTable,
			Columns: []string{agenttask.AgentTaskToProvisionedScheduleStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedschedulestep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atu.mutation.AgentTaskToAdhocPlanCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AgentTaskToAdhocPlanTable,
			Columns: []string{agenttask.AgentTaskToAdhocPlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: adhocplan.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.RemovedAgentTaskToAdhocPlanIDs(); len(nodes) > 0 && !atu.mutation.AgentTaskToAdhocPlanCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AgentTaskToAdhocPlanTable,
			Columns: []string{agenttask.AgentTaskToAdhocPlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: adhocplan.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atu.mutation.AgentTaskToAdhocPlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AgentTaskToAdhocPlanTable,
			Columns: []string{agenttask.AgentTaskToAdhocPlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: adhocplan.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, atu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{agenttask.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// AgentTaskUpdateOne is the builder for updating a single AgentTask entity.
type AgentTaskUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *AgentTaskMutation
}

// SetCommand sets the "command" field.
func (atuo *AgentTaskUpdateOne) SetCommand(a agenttask.Command) *AgentTaskUpdateOne {
	atuo.mutation.SetCommand(a)
	return atuo
}

// SetArgs sets the "args" field.
func (atuo *AgentTaskUpdateOne) SetArgs(s string) *AgentTaskUpdateOne {
	atuo.mutation.SetArgs(s)
	return atuo
}

// SetNumber sets the "number" field.
func (atuo *AgentTaskUpdateOne) SetNumber(i int) *AgentTaskUpdateOne {
	atuo.mutation.ResetNumber()
	atuo.mutation.SetNumber(i)
	return atuo
}

// AddNumber adds i to the "number" field.
func (atuo *AgentTaskUpdateOne) AddNumber(i int) *AgentTaskUpdateOne {
	atuo.mutation.AddNumber(i)
	return atuo
}

// SetOutput sets the "output" field.
func (atuo *AgentTaskUpdateOne) SetOutput(s string) *AgentTaskUpdateOne {
	atuo.mutation.SetOutput(s)
	return atuo
}

// SetNillableOutput sets the "output" field if the given value is not nil.
func (atuo *AgentTaskUpdateOne) SetNillableOutput(s *string) *AgentTaskUpdateOne {
	if s != nil {
		atuo.SetOutput(*s)
	}
	return atuo
}

// SetState sets the "state" field.
func (atuo *AgentTaskUpdateOne) SetState(a agenttask.State) *AgentTaskUpdateOne {
	atuo.mutation.SetState(a)
	return atuo
}

// SetErrorMessage sets the "error_message" field.
func (atuo *AgentTaskUpdateOne) SetErrorMessage(s string) *AgentTaskUpdateOne {
	atuo.mutation.SetErrorMessage(s)
	return atuo
}

// SetNillableErrorMessage sets the "error_message" field if the given value is not nil.
func (atuo *AgentTaskUpdateOne) SetNillableErrorMessage(s *string) *AgentTaskUpdateOne {
	if s != nil {
		atuo.SetErrorMessage(*s)
	}
	return atuo
}

// SetAgentTaskToProvisioningStepID sets the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity by ID.
func (atuo *AgentTaskUpdateOne) SetAgentTaskToProvisioningStepID(id uuid.UUID) *AgentTaskUpdateOne {
	atuo.mutation.SetAgentTaskToProvisioningStepID(id)
	return atuo
}

// SetNillableAgentTaskToProvisioningStepID sets the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity by ID if the given value is not nil.
func (atuo *AgentTaskUpdateOne) SetNillableAgentTaskToProvisioningStepID(id *uuid.UUID) *AgentTaskUpdateOne {
	if id != nil {
		atuo = atuo.SetAgentTaskToProvisioningStepID(*id)
	}
	return atuo
}

// SetAgentTaskToProvisioningStep sets the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity.
func (atuo *AgentTaskUpdateOne) SetAgentTaskToProvisioningStep(p *ProvisioningStep) *AgentTaskUpdateOne {
	return atuo.SetAgentTaskToProvisioningStepID(p.ID)
}

// SetAgentTaskToProvisionedHostID sets the "AgentTaskToProvisionedHost" edge to the ProvisionedHost entity by ID.
func (atuo *AgentTaskUpdateOne) SetAgentTaskToProvisionedHostID(id uuid.UUID) *AgentTaskUpdateOne {
	atuo.mutation.SetAgentTaskToProvisionedHostID(id)
	return atuo
}

// SetAgentTaskToProvisionedHost sets the "AgentTaskToProvisionedHost" edge to the ProvisionedHost entity.
func (atuo *AgentTaskUpdateOne) SetAgentTaskToProvisionedHost(p *ProvisionedHost) *AgentTaskUpdateOne {
	return atuo.SetAgentTaskToProvisionedHostID(p.ID)
}

// SetAgentTaskToProvisionedScheduleStepID sets the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity by ID.
func (atuo *AgentTaskUpdateOne) SetAgentTaskToProvisionedScheduleStepID(id uuid.UUID) *AgentTaskUpdateOne {
	atuo.mutation.SetAgentTaskToProvisionedScheduleStepID(id)
	return atuo
}

// SetNillableAgentTaskToProvisionedScheduleStepID sets the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity by ID if the given value is not nil.
func (atuo *AgentTaskUpdateOne) SetNillableAgentTaskToProvisionedScheduleStepID(id *uuid.UUID) *AgentTaskUpdateOne {
	if id != nil {
		atuo = atuo.SetAgentTaskToProvisionedScheduleStepID(*id)
	}
	return atuo
}

// SetAgentTaskToProvisionedScheduleStep sets the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity.
func (atuo *AgentTaskUpdateOne) SetAgentTaskToProvisionedScheduleStep(p *ProvisionedScheduleStep) *AgentTaskUpdateOne {
	return atuo.SetAgentTaskToProvisionedScheduleStepID(p.ID)
}

// AddAgentTaskToAdhocPlanIDs adds the "AgentTaskToAdhocPlan" edge to the AdhocPlan entity by IDs.
func (atuo *AgentTaskUpdateOne) AddAgentTaskToAdhocPlanIDs(ids ...uuid.UUID) *AgentTaskUpdateOne {
	atuo.mutation.AddAgentTaskToAdhocPlanIDs(ids...)
	return atuo
}

// AddAgentTaskToAdhocPlan adds the "AgentTaskToAdhocPlan" edges to the AdhocPlan entity.
func (atuo *AgentTaskUpdateOne) AddAgentTaskToAdhocPlan(a ...*AdhocPlan) *AgentTaskUpdateOne {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return atuo.AddAgentTaskToAdhocPlanIDs(ids...)
}

// Mutation returns the AgentTaskMutation object of the builder.
func (atuo *AgentTaskUpdateOne) Mutation() *AgentTaskMutation {
	return atuo.mutation
}

// ClearAgentTaskToProvisioningStep clears the "AgentTaskToProvisioningStep" edge to the ProvisioningStep entity.
func (atuo *AgentTaskUpdateOne) ClearAgentTaskToProvisioningStep() *AgentTaskUpdateOne {
	atuo.mutation.ClearAgentTaskToProvisioningStep()
	return atuo
}

// ClearAgentTaskToProvisionedHost clears the "AgentTaskToProvisionedHost" edge to the ProvisionedHost entity.
func (atuo *AgentTaskUpdateOne) ClearAgentTaskToProvisionedHost() *AgentTaskUpdateOne {
	atuo.mutation.ClearAgentTaskToProvisionedHost()
	return atuo
}

// ClearAgentTaskToProvisionedScheduleStep clears the "AgentTaskToProvisionedScheduleStep" edge to the ProvisionedScheduleStep entity.
func (atuo *AgentTaskUpdateOne) ClearAgentTaskToProvisionedScheduleStep() *AgentTaskUpdateOne {
	atuo.mutation.ClearAgentTaskToProvisionedScheduleStep()
	return atuo
}

// ClearAgentTaskToAdhocPlan clears all "AgentTaskToAdhocPlan" edges to the AdhocPlan entity.
func (atuo *AgentTaskUpdateOne) ClearAgentTaskToAdhocPlan() *AgentTaskUpdateOne {
	atuo.mutation.ClearAgentTaskToAdhocPlan()
	return atuo
}

// RemoveAgentTaskToAdhocPlanIDs removes the "AgentTaskToAdhocPlan" edge to AdhocPlan entities by IDs.
func (atuo *AgentTaskUpdateOne) RemoveAgentTaskToAdhocPlanIDs(ids ...uuid.UUID) *AgentTaskUpdateOne {
	atuo.mutation.RemoveAgentTaskToAdhocPlanIDs(ids...)
	return atuo
}

// RemoveAgentTaskToAdhocPlan removes "AgentTaskToAdhocPlan" edges to AdhocPlan entities.
func (atuo *AgentTaskUpdateOne) RemoveAgentTaskToAdhocPlan(a ...*AdhocPlan) *AgentTaskUpdateOne {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return atuo.RemoveAgentTaskToAdhocPlanIDs(ids...)
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (atuo *AgentTaskUpdateOne) Select(field string, fields ...string) *AgentTaskUpdateOne {
	atuo.fields = append([]string{field}, fields...)
	return atuo
}

// Save executes the query and returns the updated AgentTask entity.
func (atuo *AgentTaskUpdateOne) Save(ctx context.Context) (*AgentTask, error) {
	var (
		err  error
		node *AgentTask
	)
	if len(atuo.hooks) == 0 {
		if err = atuo.check(); err != nil {
			return nil, err
		}
		node, err = atuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AgentTaskMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = atuo.check(); err != nil {
				return nil, err
			}
			atuo.mutation = mutation
			node, err = atuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(atuo.hooks) - 1; i >= 0; i-- {
			if atuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = atuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, atuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*AgentTask)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from AgentTaskMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (atuo *AgentTaskUpdateOne) SaveX(ctx context.Context) *AgentTask {
	node, err := atuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (atuo *AgentTaskUpdateOne) Exec(ctx context.Context) error {
	_, err := atuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atuo *AgentTaskUpdateOne) ExecX(ctx context.Context) {
	if err := atuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (atuo *AgentTaskUpdateOne) check() error {
	if v, ok := atuo.mutation.Command(); ok {
		if err := agenttask.CommandValidator(v); err != nil {
			return &ValidationError{Name: "command", err: fmt.Errorf(`ent: validator failed for field "AgentTask.command": %w`, err)}
		}
	}
	if v, ok := atuo.mutation.State(); ok {
		if err := agenttask.StateValidator(v); err != nil {
			return &ValidationError{Name: "state", err: fmt.Errorf(`ent: validator failed for field "AgentTask.state": %w`, err)}
		}
	}
	if _, ok := atuo.mutation.AgentTaskToProvisionedHostID(); atuo.mutation.AgentTaskToProvisionedHostCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "AgentTask.AgentTaskToProvisionedHost"`)
	}
	return nil
}

func (atuo *AgentTaskUpdateOne) sqlSave(ctx context.Context) (_node *AgentTask, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   agenttask.Table,
			Columns: agenttask.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: agenttask.FieldID,
			},
		},
	}
	id, ok := atuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "AgentTask.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := atuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, agenttask.FieldID)
		for _, f := range fields {
			if !agenttask.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != agenttask.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := atuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := atuo.mutation.Command(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: agenttask.FieldCommand,
		})
	}
	if value, ok := atuo.mutation.Args(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agenttask.FieldArgs,
		})
	}
	if value, ok := atuo.mutation.Number(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: agenttask.FieldNumber,
		})
	}
	if value, ok := atuo.mutation.AddedNumber(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: agenttask.FieldNumber,
		})
	}
	if value, ok := atuo.mutation.Output(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agenttask.FieldOutput,
		})
	}
	if value, ok := atuo.mutation.State(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: agenttask.FieldState,
		})
	}
	if value, ok := atuo.mutation.ErrorMessage(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: agenttask.FieldErrorMessage,
		})
	}
	if atuo.mutation.AgentTaskToProvisioningStepCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisioningStepTable,
			Columns: []string{agenttask.AgentTaskToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisioningstep.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.AgentTaskToProvisioningStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisioningStepTable,
			Columns: []string{agenttask.AgentTaskToProvisioningStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisioningstep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atuo.mutation.AgentTaskToProvisionedHostCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedHostTable,
			Columns: []string{agenttask.AgentTaskToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedhost.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.AgentTaskToProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedHostTable,
			Columns: []string{agenttask.AgentTaskToProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedhost.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atuo.mutation.AgentTaskToProvisionedScheduleStepCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedScheduleStepTable,
			Columns: []string{agenttask.AgentTaskToProvisionedScheduleStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedschedulestep.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.AgentTaskToProvisionedScheduleStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   agenttask.AgentTaskToProvisionedScheduleStepTable,
			Columns: []string{agenttask.AgentTaskToProvisionedScheduleStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionedschedulestep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if atuo.mutation.AgentTaskToAdhocPlanCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AgentTaskToAdhocPlanTable,
			Columns: []string{agenttask.AgentTaskToAdhocPlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: adhocplan.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.RemovedAgentTaskToAdhocPlanIDs(); len(nodes) > 0 && !atuo.mutation.AgentTaskToAdhocPlanCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AgentTaskToAdhocPlanTable,
			Columns: []string{agenttask.AgentTaskToAdhocPlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: adhocplan.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := atuo.mutation.AgentTaskToAdhocPlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   agenttask.AgentTaskToAdhocPlanTable,
			Columns: []string{agenttask.AgentTaskToAdhocPlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: adhocplan.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &AgentTask{config: atuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, atuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{agenttask.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
