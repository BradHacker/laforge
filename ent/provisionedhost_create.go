// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/agentstatus"
	"github.com/gen0cide/laforge/ent/agenttask"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/ginfilemiddleware"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/provisioningscheduledstep"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/google/uuid"
)

// ProvisionedHostCreate is the builder for creating a ProvisionedHost entity.
type ProvisionedHostCreate struct {
	config
	mutation *ProvisionedHostMutation
	hooks    []Hook
}

// SetSubnetIP sets the "subnet_ip" field.
func (phc *ProvisionedHostCreate) SetSubnetIP(s string) *ProvisionedHostCreate {
	phc.mutation.SetSubnetIP(s)
	return phc
}

// SetAddonType sets the "addon_type" field.
func (phc *ProvisionedHostCreate) SetAddonType(pt provisionedhost.AddonType) *ProvisionedHostCreate {
	phc.mutation.SetAddonType(pt)
	return phc
}

// SetNillableAddonType sets the "addon_type" field if the given value is not nil.
func (phc *ProvisionedHostCreate) SetNillableAddonType(pt *provisionedhost.AddonType) *ProvisionedHostCreate {
	if pt != nil {
		phc.SetAddonType(*pt)
	}
	return phc
}

// SetVars sets the "vars" field.
func (phc *ProvisionedHostCreate) SetVars(m map[string]string) *ProvisionedHostCreate {
	phc.mutation.SetVars(m)
	return phc
}

// SetID sets the "id" field.
func (phc *ProvisionedHostCreate) SetID(u uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetID(u)
	return phc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (phc *ProvisionedHostCreate) SetNillableID(u *uuid.UUID) *ProvisionedHostCreate {
	if u != nil {
		phc.SetID(*u)
	}
	return phc
}

// SetStatusID sets the "Status" edge to the Status entity by ID.
func (phc *ProvisionedHostCreate) SetStatusID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetStatusID(id)
	return phc
}

// SetStatus sets the "Status" edge to the Status entity.
func (phc *ProvisionedHostCreate) SetStatus(s *Status) *ProvisionedHostCreate {
	return phc.SetStatusID(s.ID)
}

// SetProvisionedNetworkID sets the "ProvisionedNetwork" edge to the ProvisionedNetwork entity by ID.
func (phc *ProvisionedHostCreate) SetProvisionedNetworkID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetProvisionedNetworkID(id)
	return phc
}

// SetProvisionedNetwork sets the "ProvisionedNetwork" edge to the ProvisionedNetwork entity.
func (phc *ProvisionedHostCreate) SetProvisionedNetwork(p *ProvisionedNetwork) *ProvisionedHostCreate {
	return phc.SetProvisionedNetworkID(p.ID)
}

// SetHostID sets the "Host" edge to the Host entity by ID.
func (phc *ProvisionedHostCreate) SetHostID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetHostID(id)
	return phc
}

// SetHost sets the "Host" edge to the Host entity.
func (phc *ProvisionedHostCreate) SetHost(h *Host) *ProvisionedHostCreate {
	return phc.SetHostID(h.ID)
}

// SetEndStepPlanID sets the "EndStepPlan" edge to the Plan entity by ID.
func (phc *ProvisionedHostCreate) SetEndStepPlanID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetEndStepPlanID(id)
	return phc
}

// SetNillableEndStepPlanID sets the "EndStepPlan" edge to the Plan entity by ID if the given value is not nil.
func (phc *ProvisionedHostCreate) SetNillableEndStepPlanID(id *uuid.UUID) *ProvisionedHostCreate {
	if id != nil {
		phc = phc.SetEndStepPlanID(*id)
	}
	return phc
}

// SetEndStepPlan sets the "EndStepPlan" edge to the Plan entity.
func (phc *ProvisionedHostCreate) SetEndStepPlan(p *Plan) *ProvisionedHostCreate {
	return phc.SetEndStepPlanID(p.ID)
}

// SetBuildID sets the "Build" edge to the Build entity by ID.
func (phc *ProvisionedHostCreate) SetBuildID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetBuildID(id)
	return phc
}

// SetBuild sets the "Build" edge to the Build entity.
func (phc *ProvisionedHostCreate) SetBuild(b *Build) *ProvisionedHostCreate {
	return phc.SetBuildID(b.ID)
}

// AddProvisioningStepIDs adds the "ProvisioningSteps" edge to the ProvisioningStep entity by IDs.
func (phc *ProvisionedHostCreate) AddProvisioningStepIDs(ids ...uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.AddProvisioningStepIDs(ids...)
	return phc
}

// AddProvisioningSteps adds the "ProvisioningSteps" edges to the ProvisioningStep entity.
func (phc *ProvisionedHostCreate) AddProvisioningSteps(p ...*ProvisioningStep) *ProvisionedHostCreate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return phc.AddProvisioningStepIDs(ids...)
}

// AddProvisioningScheduledStepIDs adds the "ProvisioningScheduledSteps" edge to the ProvisioningScheduledStep entity by IDs.
func (phc *ProvisionedHostCreate) AddProvisioningScheduledStepIDs(ids ...uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.AddProvisioningScheduledStepIDs(ids...)
	return phc
}

// AddProvisioningScheduledSteps adds the "ProvisioningScheduledSteps" edges to the ProvisioningScheduledStep entity.
func (phc *ProvisionedHostCreate) AddProvisioningScheduledSteps(p ...*ProvisioningScheduledStep) *ProvisionedHostCreate {
	ids := make([]uuid.UUID, len(p))
	for i := range p {
		ids[i] = p[i].ID
	}
	return phc.AddProvisioningScheduledStepIDs(ids...)
}

// SetAgentStatusID sets the "AgentStatus" edge to the AgentStatus entity by ID.
func (phc *ProvisionedHostCreate) SetAgentStatusID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetAgentStatusID(id)
	return phc
}

// SetNillableAgentStatusID sets the "AgentStatus" edge to the AgentStatus entity by ID if the given value is not nil.
func (phc *ProvisionedHostCreate) SetNillableAgentStatusID(id *uuid.UUID) *ProvisionedHostCreate {
	if id != nil {
		phc = phc.SetAgentStatusID(*id)
	}
	return phc
}

// SetAgentStatus sets the "AgentStatus" edge to the AgentStatus entity.
func (phc *ProvisionedHostCreate) SetAgentStatus(a *AgentStatus) *ProvisionedHostCreate {
	return phc.SetAgentStatusID(a.ID)
}

// AddAgentTaskIDs adds the "AgentTasks" edge to the AgentTask entity by IDs.
func (phc *ProvisionedHostCreate) AddAgentTaskIDs(ids ...uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.AddAgentTaskIDs(ids...)
	return phc
}

// AddAgentTasks adds the "AgentTasks" edges to the AgentTask entity.
func (phc *ProvisionedHostCreate) AddAgentTasks(a ...*AgentTask) *ProvisionedHostCreate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return phc.AddAgentTaskIDs(ids...)
}

// SetPlanID sets the "Plan" edge to the Plan entity by ID.
func (phc *ProvisionedHostCreate) SetPlanID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetPlanID(id)
	return phc
}

// SetNillablePlanID sets the "Plan" edge to the Plan entity by ID if the given value is not nil.
func (phc *ProvisionedHostCreate) SetNillablePlanID(id *uuid.UUID) *ProvisionedHostCreate {
	if id != nil {
		phc = phc.SetPlanID(*id)
	}
	return phc
}

// SetPlan sets the "Plan" edge to the Plan entity.
func (phc *ProvisionedHostCreate) SetPlan(p *Plan) *ProvisionedHostCreate {
	return phc.SetPlanID(p.ID)
}

// SetGinFileMiddlewareID sets the "GinFileMiddleware" edge to the GinFileMiddleware entity by ID.
func (phc *ProvisionedHostCreate) SetGinFileMiddlewareID(id uuid.UUID) *ProvisionedHostCreate {
	phc.mutation.SetGinFileMiddlewareID(id)
	return phc
}

// SetNillableGinFileMiddlewareID sets the "GinFileMiddleware" edge to the GinFileMiddleware entity by ID if the given value is not nil.
func (phc *ProvisionedHostCreate) SetNillableGinFileMiddlewareID(id *uuid.UUID) *ProvisionedHostCreate {
	if id != nil {
		phc = phc.SetGinFileMiddlewareID(*id)
	}
	return phc
}

// SetGinFileMiddleware sets the "GinFileMiddleware" edge to the GinFileMiddleware entity.
func (phc *ProvisionedHostCreate) SetGinFileMiddleware(g *GinFileMiddleware) *ProvisionedHostCreate {
	return phc.SetGinFileMiddlewareID(g.ID)
}

// Mutation returns the ProvisionedHostMutation object of the builder.
func (phc *ProvisionedHostCreate) Mutation() *ProvisionedHostMutation {
	return phc.mutation
}

// Save creates the ProvisionedHost in the database.
func (phc *ProvisionedHostCreate) Save(ctx context.Context) (*ProvisionedHost, error) {
	var (
		err  error
		node *ProvisionedHost
	)
	phc.defaults()
	if len(phc.hooks) == 0 {
		if err = phc.check(); err != nil {
			return nil, err
		}
		node, err = phc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*ProvisionedHostMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = phc.check(); err != nil {
				return nil, err
			}
			phc.mutation = mutation
			if node, err = phc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(phc.hooks) - 1; i >= 0; i-- {
			if phc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = phc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, phc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*ProvisionedHost)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from ProvisionedHostMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (phc *ProvisionedHostCreate) SaveX(ctx context.Context) *ProvisionedHost {
	v, err := phc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (phc *ProvisionedHostCreate) Exec(ctx context.Context) error {
	_, err := phc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (phc *ProvisionedHostCreate) ExecX(ctx context.Context) {
	if err := phc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (phc *ProvisionedHostCreate) defaults() {
	if _, ok := phc.mutation.ID(); !ok {
		v := provisionedhost.DefaultID()
		phc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (phc *ProvisionedHostCreate) check() error {
	if _, ok := phc.mutation.SubnetIP(); !ok {
		return &ValidationError{Name: "subnet_ip", err: errors.New(`ent: missing required field "ProvisionedHost.subnet_ip"`)}
	}
	if v, ok := phc.mutation.AddonType(); ok {
		if err := provisionedhost.AddonTypeValidator(v); err != nil {
			return &ValidationError{Name: "addon_type", err: fmt.Errorf(`ent: validator failed for field "ProvisionedHost.addon_type": %w`, err)}
		}
	}
	if _, ok := phc.mutation.Vars(); !ok {
		return &ValidationError{Name: "vars", err: errors.New(`ent: missing required field "ProvisionedHost.vars"`)}
	}
	if _, ok := phc.mutation.StatusID(); !ok {
		return &ValidationError{Name: "Status", err: errors.New(`ent: missing required edge "ProvisionedHost.Status"`)}
	}
	if _, ok := phc.mutation.ProvisionedNetworkID(); !ok {
		return &ValidationError{Name: "ProvisionedNetwork", err: errors.New(`ent: missing required edge "ProvisionedHost.ProvisionedNetwork"`)}
	}
	if _, ok := phc.mutation.HostID(); !ok {
		return &ValidationError{Name: "Host", err: errors.New(`ent: missing required edge "ProvisionedHost.Host"`)}
	}
	if _, ok := phc.mutation.BuildID(); !ok {
		return &ValidationError{Name: "Build", err: errors.New(`ent: missing required edge "ProvisionedHost.Build"`)}
	}
	return nil
}

func (phc *ProvisionedHostCreate) sqlSave(ctx context.Context) (*ProvisionedHost, error) {
	_node, _spec := phc.createSpec()
	if err := sqlgraph.CreateNode(ctx, phc.driver, _spec); err != nil {
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
	return _node, nil
}

func (phc *ProvisionedHostCreate) createSpec() (*ProvisionedHost, *sqlgraph.CreateSpec) {
	var (
		_node = &ProvisionedHost{config: phc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: provisionedhost.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: provisionedhost.FieldID,
			},
		}
	)
	if id, ok := phc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := phc.mutation.SubnetIP(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: provisionedhost.FieldSubnetIP,
		})
		_node.SubnetIP = value
	}
	if value, ok := phc.mutation.AddonType(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: provisionedhost.FieldAddonType,
		})
		_node.AddonType = &value
	}
	if value, ok := phc.mutation.Vars(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: provisionedhost.FieldVars,
		})
		_node.Vars = value
	}
	if nodes := phc.mutation.StatusIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   provisionedhost.StatusTable,
			Columns: []string{provisionedhost.StatusColumn},
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
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.ProvisionedNetworkIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisionedhost.ProvisionedNetworkTable,
			Columns: []string{provisionedhost.ProvisionedNetworkColumn},
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
		_node.provisioned_host_provisioned_network = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.HostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisionedhost.HostTable,
			Columns: []string{provisionedhost.HostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: host.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioned_host_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.EndStepPlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisionedhost.EndStepPlanTable,
			Columns: []string{provisionedhost.EndStepPlanColumn},
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
		_node.provisioned_host_end_step_plan = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.BuildIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisionedhost.BuildTable,
			Columns: []string{provisionedhost.BuildColumn},
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
		_node.provisioned_host_build = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.ProvisioningStepsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   provisionedhost.ProvisioningStepsTable,
			Columns: []string{provisionedhost.ProvisioningStepsColumn},
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
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.ProvisioningScheduledStepsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   provisionedhost.ProvisioningScheduledStepsTable,
			Columns: []string{provisionedhost.ProvisioningScheduledStepsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: provisioningscheduledstep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.AgentStatusIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   provisionedhost.AgentStatusTable,
			Columns: []string{provisionedhost.AgentStatusColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: agentstatus.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.agent_status_provisioned_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.AgentTasksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   provisionedhost.AgentTasksTable,
			Columns: []string{provisionedhost.AgentTasksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: agenttask.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.PlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   provisionedhost.PlanTable,
			Columns: []string{provisionedhost.PlanColumn},
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
		_node.plan_provisioned_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := phc.mutation.GinFileMiddlewareIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   provisionedhost.GinFileMiddlewareTable,
			Columns: []string{provisionedhost.GinFileMiddlewareColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: ginfilemiddleware.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.gin_file_middleware_provisioned_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ProvisionedHostCreateBulk is the builder for creating many ProvisionedHost entities in bulk.
type ProvisionedHostCreateBulk struct {
	config
	builders []*ProvisionedHostCreate
}

// Save creates the ProvisionedHost entities in the database.
func (phcb *ProvisionedHostCreateBulk) Save(ctx context.Context) ([]*ProvisionedHost, error) {
	specs := make([]*sqlgraph.CreateSpec, len(phcb.builders))
	nodes := make([]*ProvisionedHost, len(phcb.builders))
	mutators := make([]Mutator, len(phcb.builders))
	for i := range phcb.builders {
		func(i int, root context.Context) {
			builder := phcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ProvisionedHostMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, phcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, phcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, phcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (phcb *ProvisionedHostCreateBulk) SaveX(ctx context.Context) []*ProvisionedHost {
	v, err := phcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (phcb *ProvisionedHostCreateBulk) Exec(ctx context.Context) error {
	_, err := phcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (phcb *ProvisionedHostCreateBulk) ExecX(ctx context.Context) {
	if err := phcb.Exec(ctx); err != nil {
		panic(err)
	}
}
