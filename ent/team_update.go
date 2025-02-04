// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/gen0cide/laforge/ent/team"
	"github.com/google/uuid"
)

// TeamUpdate is the builder for updating Team entities.
type TeamUpdate struct {
	config
	hooks    []Hook
	mutation *TeamMutation
}

// Where appends a list predicates to the TeamUpdate builder.
func (tu *TeamUpdate) Where(ps ...predicate.Team) *TeamUpdate {
	tu.mutation.Where(ps...)
	return tu
}

// SetTeamNumber sets the "team_number" field.
func (tu *TeamUpdate) SetTeamNumber(i int) *TeamUpdate {
	tu.mutation.ResetTeamNumber()
	tu.mutation.SetTeamNumber(i)
	return tu
}

// AddTeamNumber adds i to the "team_number" field.
func (tu *TeamUpdate) AddTeamNumber(i int) *TeamUpdate {
	tu.mutation.AddTeamNumber(i)
	return tu
}

// SetVars sets the "vars" field.
func (tu *TeamUpdate) SetVars(m map[string]string) *TeamUpdate {
	tu.mutation.SetVars(m)
	return tu
}

// SetBuildID sets the "Build" edge to the Build entity by ID.
func (tu *TeamUpdate) SetBuildID(id uuid.UUID) *TeamUpdate {
	tu.mutation.SetBuildID(id)
	return tu
}

// SetBuild sets the "Build" edge to the Build entity.
func (tu *TeamUpdate) SetBuild(b *Build) *TeamUpdate {
	return tu.SetBuildID(b.ID)
}

// SetStatusID sets the "Status" edge to the Status entity by ID.
func (tu *TeamUpdate) SetStatusID(id uuid.UUID) *TeamUpdate {
	tu.mutation.SetStatusID(id)
	return tu
}

// SetNillableStatusID sets the "Status" edge to the Status entity by ID if the given value is not nil.
func (tu *TeamUpdate) SetNillableStatusID(id *uuid.UUID) *TeamUpdate {
	if id != nil {
		tu = tu.SetStatusID(*id)
	}
	return tu
}

// SetStatus sets the "Status" edge to the Status entity.
func (tu *TeamUpdate) SetStatus(s *Status) *TeamUpdate {
	return tu.SetStatusID(s.ID)
}

// AddProvisionedNetworkIDs adds the "ProvisionedNetworks" edge to the ProvisionedNetwork entity by IDs.
func (tu *TeamUpdate) AddProvisionedNetworkIDs(ids ...uuid.UUID) *TeamUpdate {
	tu.mutation.AddProvisionedNetworkIDs(ids...)
	return tu
}

// AddProvisionedNetworks adds the "ProvisionedNetworks" edges to the ProvisionedNetwork entity.
func (tu *TeamUpdate) AddProvisionedNetworks(p ...*ProvisionedNetwork) *TeamUpdate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return tu.AddProvisionedNetworkIDs(ids...)
}

// SetPlanID sets the "Plan" edge to the Plan entity by ID.
func (tu *TeamUpdate) SetPlanID(id uuid.UUID) *TeamUpdate {
	tu.mutation.SetPlanID(id)
	return tu
}

// SetNillablePlanID sets the "Plan" edge to the Plan entity by ID if the given value is not nil.
func (tu *TeamUpdate) SetNillablePlanID(id *uuid.UUID) *TeamUpdate {
	if id != nil {
		tu = tu.SetPlanID(*id)
	}
	return tu
}

// SetPlan sets the "Plan" edge to the Plan entity.
func (tu *TeamUpdate) SetPlan(p *Plan) *TeamUpdate {
	return tu.SetPlanID(p.ID)
}

// Mutation returns the TeamMutation object of the builder.
func (tu *TeamUpdate) Mutation() *TeamMutation {
	return tu.mutation
}

// ClearBuild clears the "Build" edge to the Build entity.
func (tu *TeamUpdate) ClearBuild() *TeamUpdate {
	tu.mutation.ClearBuild()
	return tu
}

// ClearStatus clears the "Status" edge to the Status entity.
func (tu *TeamUpdate) ClearStatus() *TeamUpdate {
	tu.mutation.ClearStatus()
	return tu
}

// ClearProvisionedNetworks clears all "ProvisionedNetworks" edges to the ProvisionedNetwork entity.
func (tu *TeamUpdate) ClearProvisionedNetworks() *TeamUpdate {
	tu.mutation.ClearProvisionedNetworks()
	return tu
}

// RemoveProvisionedNetworkIDs removes the "ProvisionedNetworks" edge to ProvisionedNetwork entities by IDs.
func (tu *TeamUpdate) RemoveProvisionedNetworkIDs(ids ...uuid.UUID) *TeamUpdate {
	tu.mutation.RemoveProvisionedNetworkIDs(ids...)
	return tu
}

// RemoveProvisionedNetworks removes "ProvisionedNetworks" edges to ProvisionedNetwork entities.
func (tu *TeamUpdate) RemoveProvisionedNetworks(p ...*ProvisionedNetwork) *TeamUpdate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return tu.RemoveProvisionedNetworkIDs(ids...)
}

// ClearPlan clears the "Plan" edge to the Plan entity.
func (tu *TeamUpdate) ClearPlan() *TeamUpdate {
	tu.mutation.ClearPlan()
	return tu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (tu *TeamUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(tu.hooks) == 0 {
		if err = tu.check(); err != nil {
			return 0, err
		}
		affected, err = tu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*TeamMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = tu.check(); err != nil {
				return 0, err
			}
			tu.mutation = mutation
			affected, err = tu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(tu.hooks) - 1; i >= 0; i-- {
			if tu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = tu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, tu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (tu *TeamUpdate) SaveX(ctx context.Context) int {
	affected, err := tu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (tu *TeamUpdate) Exec(ctx context.Context) error {
	_, err := tu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tu *TeamUpdate) ExecX(ctx context.Context) {
	if err := tu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (tu *TeamUpdate) check() error {
	if _, ok := tu.mutation.BuildID(); tu.mutation.BuildCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "Team.Build"`)
	}
	return nil
}

func (tu *TeamUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   team.Table,
			Columns: team.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: team.FieldID,
			},
		},
	}
	if ps := tu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tu.mutation.TeamNumber(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: team.FieldTeamNumber,
		})
	}
	if value, ok := tu.mutation.AddedTeamNumber(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: team.FieldTeamNumber,
		})
	}
	if value, ok := tu.mutation.Vars(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: team.FieldVars,
		})
	}
	if tu.mutation.BuildCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   team.BuildTable,
			Columns: []string{team.BuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: build.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tu.mutation.BuildIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   team.BuildTable,
			Columns: []string{team.BuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: build.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tu.mutation.StatusCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   team.StatusTable,
			Columns: []string{team.StatusColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: status.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tu.mutation.StatusIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   team.StatusTable,
			Columns: []string{team.StatusColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: status.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tu.mutation.ProvisionedNetworksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   team.ProvisionedNetworksTable,
			Columns: []string{team.ProvisionedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tu.mutation.RemovedProvisionedNetworksIDs(); len(nodes) > 0 && !tu.mutation.ProvisionedNetworksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   team.ProvisionedNetworksTable,
			Columns: []string{team.ProvisionedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tu.mutation.ProvisionedNetworksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   team.ProvisionedNetworksTable,
			Columns: []string{team.ProvisionedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tu.mutation.PlanCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   team.PlanTable,
			Columns: []string{team.PlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: plan.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tu.mutation.PlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   team.PlanTable,
			Columns: []string{team.PlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: plan.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, tu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{team.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// TeamUpdateOne is the builder for updating a single Team entity.
type TeamUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *TeamMutation
}

// SetTeamNumber sets the "team_number" field.
func (tuo *TeamUpdateOne) SetTeamNumber(i int) *TeamUpdateOne {
	tuo.mutation.ResetTeamNumber()
	tuo.mutation.SetTeamNumber(i)
	return tuo
}

// AddTeamNumber adds i to the "team_number" field.
func (tuo *TeamUpdateOne) AddTeamNumber(i int) *TeamUpdateOne {
	tuo.mutation.AddTeamNumber(i)
	return tuo
}

// SetVars sets the "vars" field.
func (tuo *TeamUpdateOne) SetVars(m map[string]string) *TeamUpdateOne {
	tuo.mutation.SetVars(m)
	return tuo
}

// SetBuildID sets the "Build" edge to the Build entity by ID.
func (tuo *TeamUpdateOne) SetBuildID(id uuid.UUID) *TeamUpdateOne {
	tuo.mutation.SetBuildID(id)
	return tuo
}

// SetBuild sets the "Build" edge to the Build entity.
func (tuo *TeamUpdateOne) SetBuild(b *Build) *TeamUpdateOne {
	return tuo.SetBuildID(b.ID)
}

// SetStatusID sets the "Status" edge to the Status entity by ID.
func (tuo *TeamUpdateOne) SetStatusID(id uuid.UUID) *TeamUpdateOne {
	tuo.mutation.SetStatusID(id)
	return tuo
}

// SetNillableStatusID sets the "Status" edge to the Status entity by ID if the given value is not nil.
func (tuo *TeamUpdateOne) SetNillableStatusID(id *uuid.UUID) *TeamUpdateOne {
	if id != nil {
		tuo = tuo.SetStatusID(*id)
	}
	return tuo
}

// SetStatus sets the "Status" edge to the Status entity.
func (tuo *TeamUpdateOne) SetStatus(s *Status) *TeamUpdateOne {
	return tuo.SetStatusID(s.ID)
}

// AddProvisionedNetworkIDs adds the "ProvisionedNetworks" edge to the ProvisionedNetwork entity by IDs.
func (tuo *TeamUpdateOne) AddProvisionedNetworkIDs(ids ...uuid.UUID) *TeamUpdateOne {
	tuo.mutation.AddProvisionedNetworkIDs(ids...)
	return tuo
}

// AddProvisionedNetworks adds the "ProvisionedNetworks" edges to the ProvisionedNetwork entity.
func (tuo *TeamUpdateOne) AddProvisionedNetworks(p ...*ProvisionedNetwork) *TeamUpdateOne {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return tuo.AddProvisionedNetworkIDs(ids...)
}

// SetPlanID sets the "Plan" edge to the Plan entity by ID.
func (tuo *TeamUpdateOne) SetPlanID(id uuid.UUID) *TeamUpdateOne {
	tuo.mutation.SetPlanID(id)
	return tuo
}

// SetNillablePlanID sets the "Plan" edge to the Plan entity by ID if the given value is not nil.
func (tuo *TeamUpdateOne) SetNillablePlanID(id *uuid.UUID) *TeamUpdateOne {
	if id != nil {
		tuo = tuo.SetPlanID(*id)
	}
	return tuo
}

// SetPlan sets the "Plan" edge to the Plan entity.
func (tuo *TeamUpdateOne) SetPlan(p *Plan) *TeamUpdateOne {
	return tuo.SetPlanID(p.ID)
}

// Mutation returns the TeamMutation object of the builder.
func (tuo *TeamUpdateOne) Mutation() *TeamMutation {
	return tuo.mutation
}

// ClearBuild clears the "Build" edge to the Build entity.
func (tuo *TeamUpdateOne) ClearBuild() *TeamUpdateOne {
	tuo.mutation.ClearBuild()
	return tuo
}

// ClearStatus clears the "Status" edge to the Status entity.
func (tuo *TeamUpdateOne) ClearStatus() *TeamUpdateOne {
	tuo.mutation.ClearStatus()
	return tuo
}

// ClearProvisionedNetworks clears all "ProvisionedNetworks" edges to the ProvisionedNetwork entity.
func (tuo *TeamUpdateOne) ClearProvisionedNetworks() *TeamUpdateOne {
	tuo.mutation.ClearProvisionedNetworks()
	return tuo
}

// RemoveProvisionedNetworkIDs removes the "ProvisionedNetworks" edge to ProvisionedNetwork entities by IDs.
func (tuo *TeamUpdateOne) RemoveProvisionedNetworkIDs(ids ...uuid.UUID) *TeamUpdateOne {
	tuo.mutation.RemoveProvisionedNetworkIDs(ids...)
	return tuo
}

// RemoveProvisionedNetworks removes "ProvisionedNetworks" edges to ProvisionedNetwork entities.
func (tuo *TeamUpdateOne) RemoveProvisionedNetworks(p ...*ProvisionedNetwork) *TeamUpdateOne {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return tuo.RemoveProvisionedNetworkIDs(ids...)
}

// ClearPlan clears the "Plan" edge to the Plan entity.
func (tuo *TeamUpdateOne) ClearPlan() *TeamUpdateOne {
	tuo.mutation.ClearPlan()
	return tuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (tuo *TeamUpdateOne) Select(field string, fields ...string) *TeamUpdateOne {
	tuo.fields = append([]string{field}, fields...)
	return tuo
}

// Save executes the query and returns the updated Team entity.
func (tuo *TeamUpdateOne) Save(ctx context.Context) (*Team, error) {
	var (
		err  error
		node *Team
	)
	if len(tuo.hooks) == 0 {
		if err = tuo.check(); err != nil {
			return nil, err
		}
		node, err = tuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*TeamMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = tuo.check(); err != nil {
				return nil, err
			}
			tuo.mutation = mutation
			node, err = tuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(tuo.hooks) - 1; i >= 0; i-- {
			if tuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = tuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, tuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*Team)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from TeamMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (tuo *TeamUpdateOne) SaveX(ctx context.Context) *Team {
	node, err := tuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (tuo *TeamUpdateOne) Exec(ctx context.Context) error {
	_, err := tuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (tuo *TeamUpdateOne) ExecX(ctx context.Context) {
	if err := tuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (tuo *TeamUpdateOne) check() error {
	if _, ok := tuo.mutation.BuildID(); tuo.mutation.BuildCleared() && !ok {
		return errors.New(`ent: clearing a required unique edge "Team.Build"`)
	}
	return nil
}

func (tuo *TeamUpdateOne) sqlSave(ctx context.Context) (_node *Team, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   team.Table,
			Columns: team.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: team.FieldID,
			},
		},
	}
	id, ok := tuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Team.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := tuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, team.FieldID)
		for _, f := range fields {
			if !team.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != team.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := tuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := tuo.mutation.TeamNumber(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: team.FieldTeamNumber,
		})
	}
	if value, ok := tuo.mutation.AddedTeamNumber(); ok {
		_spec.Fields.Add = append(_spec.Fields.Add, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: team.FieldTeamNumber,
		})
	}
	if value, ok := tuo.mutation.Vars(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: team.FieldVars,
		})
	}
	if tuo.mutation.BuildCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   team.BuildTable,
			Columns: []string{team.BuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: build.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tuo.mutation.BuildIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   team.BuildTable,
			Columns: []string{team.BuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: build.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tuo.mutation.StatusCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   team.StatusTable,
			Columns: []string{team.StatusColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: status.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tuo.mutation.StatusIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   team.StatusTable,
			Columns: []string{team.StatusColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: status.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tuo.mutation.ProvisionedNetworksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   team.ProvisionedNetworksTable,
			Columns: []string{team.ProvisionedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tuo.mutation.RemovedProvisionedNetworksIDs(); len(nodes) > 0 && !tuo.mutation.ProvisionedNetworksCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   team.ProvisionedNetworksTable,
			Columns: []string{team.ProvisionedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tuo.mutation.ProvisionedNetworksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   team.ProvisionedNetworksTable,
			Columns: []string{team.ProvisionedNetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisionednetwork.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if tuo.mutation.PlanCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   team.PlanTable,
			Columns: []string{team.PlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: plan.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := tuo.mutation.PlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   team.PlanTable,
			Columns: []string{team.PlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: plan.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Team{config: tuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, tuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{team.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
