// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/agenttask"
	"github.com/gen0cide/laforge/ent/ansible"
	"github.com/gen0cide/laforge/ent/command"
	"github.com/gen0cide/laforge/ent/dnsrecord"
	"github.com/gen0cide/laforge/ent/filedelete"
	"github.com/gen0cide/laforge/ent/filedownload"
	"github.com/gen0cide/laforge/ent/fileextract"
	"github.com/gen0cide/laforge/ent/ginfilemiddleware"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisioningscheduledstep"
	"github.com/gen0cide/laforge/ent/scheduledstep"
	"github.com/gen0cide/laforge/ent/script"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/google/uuid"
)

// ProvisioningScheduledStepCreate is the builder for creating a ProvisioningScheduledStep entity.
type ProvisioningScheduledStepCreate struct {
	config
	mutation *ProvisioningScheduledStepMutation
	hooks    []Hook
}

// SetType sets the "type" field.
func (pssc *ProvisioningScheduledStepCreate) SetType(pr provisioningscheduledstep.Type) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetType(pr)
	return pssc
}

// SetRunTime sets the "run_time" field.
func (pssc *ProvisioningScheduledStepCreate) SetRunTime(t time.Time) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetRunTime(t)
	return pssc
}

// SetID sets the "id" field.
func (pssc *ProvisioningScheduledStepCreate) SetID(u uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetID(u)
	return pssc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableID(u *uuid.UUID) *ProvisioningScheduledStepCreate {
	if u != nil {
		pssc.SetID(*u)
	}
	return pssc
}

// SetStatusID sets the "Status" edge to the Status entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetStatusID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetStatusID(id)
	return pssc
}

// SetNillableStatusID sets the "Status" edge to the Status entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableStatusID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetStatusID(*id)
	}
	return pssc
}

// SetStatus sets the "Status" edge to the Status entity.
func (pssc *ProvisioningScheduledStepCreate) SetStatus(s *Status) *ProvisioningScheduledStepCreate {
	return pssc.SetStatusID(s.ID)
}

// SetScheduledStepID sets the "ScheduledStep" edge to the ScheduledStep entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetScheduledStepID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetScheduledStepID(id)
	return pssc
}

// SetScheduledStep sets the "ScheduledStep" edge to the ScheduledStep entity.
func (pssc *ProvisioningScheduledStepCreate) SetScheduledStep(s *ScheduledStep) *ProvisioningScheduledStepCreate {
	return pssc.SetScheduledStepID(s.ID)
}

// SetProvisionedHostID sets the "ProvisionedHost" edge to the ProvisionedHost entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetProvisionedHostID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetProvisionedHostID(id)
	return pssc
}

// SetProvisionedHost sets the "ProvisionedHost" edge to the ProvisionedHost entity.
func (pssc *ProvisioningScheduledStepCreate) SetProvisionedHost(p *ProvisionedHost) *ProvisioningScheduledStepCreate {
	return pssc.SetProvisionedHostID(p.ID)
}

// SetScriptID sets the "Script" edge to the Script entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetScriptID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetScriptID(id)
	return pssc
}

// SetNillableScriptID sets the "Script" edge to the Script entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableScriptID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetScriptID(*id)
	}
	return pssc
}

// SetScript sets the "Script" edge to the Script entity.
func (pssc *ProvisioningScheduledStepCreate) SetScript(s *Script) *ProvisioningScheduledStepCreate {
	return pssc.SetScriptID(s.ID)
}

// SetCommandID sets the "Command" edge to the Command entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetCommandID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetCommandID(id)
	return pssc
}

// SetNillableCommandID sets the "Command" edge to the Command entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableCommandID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetCommandID(*id)
	}
	return pssc
}

// SetCommand sets the "Command" edge to the Command entity.
func (pssc *ProvisioningScheduledStepCreate) SetCommand(c *Command) *ProvisioningScheduledStepCreate {
	return pssc.SetCommandID(c.ID)
}

// SetDNSRecordID sets the "DNSRecord" edge to the DNSRecord entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetDNSRecordID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetDNSRecordID(id)
	return pssc
}

// SetNillableDNSRecordID sets the "DNSRecord" edge to the DNSRecord entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableDNSRecordID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetDNSRecordID(*id)
	}
	return pssc
}

// SetDNSRecord sets the "DNSRecord" edge to the DNSRecord entity.
func (pssc *ProvisioningScheduledStepCreate) SetDNSRecord(d *DNSRecord) *ProvisioningScheduledStepCreate {
	return pssc.SetDNSRecordID(d.ID)
}

// SetFileDeleteID sets the "FileDelete" edge to the FileDelete entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetFileDeleteID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetFileDeleteID(id)
	return pssc
}

// SetNillableFileDeleteID sets the "FileDelete" edge to the FileDelete entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableFileDeleteID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetFileDeleteID(*id)
	}
	return pssc
}

// SetFileDelete sets the "FileDelete" edge to the FileDelete entity.
func (pssc *ProvisioningScheduledStepCreate) SetFileDelete(f *FileDelete) *ProvisioningScheduledStepCreate {
	return pssc.SetFileDeleteID(f.ID)
}

// SetFileDownloadID sets the "FileDownload" edge to the FileDownload entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetFileDownloadID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetFileDownloadID(id)
	return pssc
}

// SetNillableFileDownloadID sets the "FileDownload" edge to the FileDownload entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableFileDownloadID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetFileDownloadID(*id)
	}
	return pssc
}

// SetFileDownload sets the "FileDownload" edge to the FileDownload entity.
func (pssc *ProvisioningScheduledStepCreate) SetFileDownload(f *FileDownload) *ProvisioningScheduledStepCreate {
	return pssc.SetFileDownloadID(f.ID)
}

// SetFileExtractID sets the "FileExtract" edge to the FileExtract entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetFileExtractID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetFileExtractID(id)
	return pssc
}

// SetNillableFileExtractID sets the "FileExtract" edge to the FileExtract entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableFileExtractID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetFileExtractID(*id)
	}
	return pssc
}

// SetFileExtract sets the "FileExtract" edge to the FileExtract entity.
func (pssc *ProvisioningScheduledStepCreate) SetFileExtract(f *FileExtract) *ProvisioningScheduledStepCreate {
	return pssc.SetFileExtractID(f.ID)
}

// SetAnsibleID sets the "Ansible" edge to the Ansible entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetAnsibleID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetAnsibleID(id)
	return pssc
}

// SetNillableAnsibleID sets the "Ansible" edge to the Ansible entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableAnsibleID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetAnsibleID(*id)
	}
	return pssc
}

// SetAnsible sets the "Ansible" edge to the Ansible entity.
func (pssc *ProvisioningScheduledStepCreate) SetAnsible(a *Ansible) *ProvisioningScheduledStepCreate {
	return pssc.SetAnsibleID(a.ID)
}

// AddAgentTaskIDs adds the "AgentTasks" edge to the AgentTask entity by IDs.
func (pssc *ProvisioningScheduledStepCreate) AddAgentTaskIDs(ids ...uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.AddAgentTaskIDs(ids...)
	return pssc
}

// AddAgentTasks adds the "AgentTasks" edges to the AgentTask entity.
func (pssc *ProvisioningScheduledStepCreate) AddAgentTasks(a ...*AgentTask) *ProvisioningScheduledStepCreate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return pssc.AddAgentTaskIDs(ids...)
}

// SetPlanID sets the "Plan" edge to the Plan entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetPlanID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetPlanID(id)
	return pssc
}

// SetNillablePlanID sets the "Plan" edge to the Plan entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillablePlanID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetPlanID(*id)
	}
	return pssc
}

// SetPlan sets the "Plan" edge to the Plan entity.
func (pssc *ProvisioningScheduledStepCreate) SetPlan(p *Plan) *ProvisioningScheduledStepCreate {
	return pssc.SetPlanID(p.ID)
}

// SetGinFileMiddlewareID sets the "GinFileMiddleware" edge to the GinFileMiddleware entity by ID.
func (pssc *ProvisioningScheduledStepCreate) SetGinFileMiddlewareID(id uuid.UUID) *ProvisioningScheduledStepCreate {
	pssc.mutation.SetGinFileMiddlewareID(id)
	return pssc
}

// SetNillableGinFileMiddlewareID sets the "GinFileMiddleware" edge to the GinFileMiddleware entity by ID if the given value is not nil.
func (pssc *ProvisioningScheduledStepCreate) SetNillableGinFileMiddlewareID(id *uuid.UUID) *ProvisioningScheduledStepCreate {
	if id != nil {
		pssc = pssc.SetGinFileMiddlewareID(*id)
	}
	return pssc
}

// SetGinFileMiddleware sets the "GinFileMiddleware" edge to the GinFileMiddleware entity.
func (pssc *ProvisioningScheduledStepCreate) SetGinFileMiddleware(g *GinFileMiddleware) *ProvisioningScheduledStepCreate {
	return pssc.SetGinFileMiddlewareID(g.ID)
}

// Mutation returns the ProvisioningScheduledStepMutation object of the builder.
func (pssc *ProvisioningScheduledStepCreate) Mutation() *ProvisioningScheduledStepMutation {
	return pssc.mutation
}

// Save creates the ProvisioningScheduledStep in the database.
func (pssc *ProvisioningScheduledStepCreate) Save(ctx context.Context) (*ProvisioningScheduledStep, error) {
	pssc.defaults()
	return withHooks(ctx, pssc.sqlSave, pssc.mutation, pssc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (pssc *ProvisioningScheduledStepCreate) SaveX(ctx context.Context) *ProvisioningScheduledStep {
	v, err := pssc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (pssc *ProvisioningScheduledStepCreate) Exec(ctx context.Context) error {
	_, err := pssc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pssc *ProvisioningScheduledStepCreate) ExecX(ctx context.Context) {
	if err := pssc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (pssc *ProvisioningScheduledStepCreate) defaults() {
	if _, ok := pssc.mutation.ID(); !ok {
		v := provisioningscheduledstep.DefaultID()
		pssc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pssc *ProvisioningScheduledStepCreate) check() error {
	if _, ok := pssc.mutation.GetType(); !ok {
		return &ValidationError{Name: "type", err: errors.New(`ent: missing required field "ProvisioningScheduledStep.type"`)}
	}
	if v, ok := pssc.mutation.GetType(); ok {
		if err := provisioningscheduledstep.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "ProvisioningScheduledStep.type": %w`, err)}
		}
	}
	if _, ok := pssc.mutation.RunTime(); !ok {
		return &ValidationError{Name: "run_time", err: errors.New(`ent: missing required field "ProvisioningScheduledStep.run_time"`)}
	}
	if _, ok := pssc.mutation.ScheduledStepID(); !ok {
		return &ValidationError{Name: "ScheduledStep", err: errors.New(`ent: missing required edge "ProvisioningScheduledStep.ScheduledStep"`)}
	}
	if _, ok := pssc.mutation.ProvisionedHostID(); !ok {
		return &ValidationError{Name: "ProvisionedHost", err: errors.New(`ent: missing required edge "ProvisioningScheduledStep.ProvisionedHost"`)}
	}
	return nil
}

func (pssc *ProvisioningScheduledStepCreate) sqlSave(ctx context.Context) (*ProvisioningScheduledStep, error) {
	if err := pssc.check(); err != nil {
		return nil, err
	}
	_node, _spec := pssc.createSpec()
	if err := sqlgraph.CreateNode(ctx, pssc.driver, _spec); err != nil {
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
	pssc.mutation.id = &_node.ID
	pssc.mutation.done = true
	return _node, nil
}

func (pssc *ProvisioningScheduledStepCreate) createSpec() (*ProvisioningScheduledStep, *sqlgraph.CreateSpec) {
	var (
		_node = &ProvisioningScheduledStep{config: pssc.config}
		_spec = sqlgraph.NewCreateSpec(provisioningscheduledstep.Table, sqlgraph.NewFieldSpec(provisioningscheduledstep.FieldID, field.TypeUUID))
	)
	if id, ok := pssc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := pssc.mutation.GetType(); ok {
		_spec.SetField(provisioningscheduledstep.FieldType, field.TypeEnum, value)
		_node.Type = value
	}
	if value, ok := pssc.mutation.RunTime(); ok {
		_spec.SetField(provisioningscheduledstep.FieldRunTime, field.TypeTime, value)
		_node.RunTime = value
	}
	if nodes := pssc.mutation.StatusIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: false,
			Table:   provisioningscheduledstep.StatusTable,
			Columns: []string{provisioningscheduledstep.StatusColumn},
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
	if nodes := pssc.mutation.ScheduledStepIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.ScheduledStepTable,
			Columns: []string{provisioningscheduledstep.ScheduledStepColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(scheduledstep.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_scheduled_step = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.ProvisionedHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.ProvisionedHostTable,
			Columns: []string{provisioningscheduledstep.ProvisionedHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(provisionedhost.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_provisioned_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.ScriptIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.ScriptTable,
			Columns: []string{provisioningscheduledstep.ScriptColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(script.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_script = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.CommandIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.CommandTable,
			Columns: []string{provisioningscheduledstep.CommandColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(command.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_command = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.DNSRecordIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.DNSRecordTable,
			Columns: []string{provisioningscheduledstep.DNSRecordColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(dnsrecord.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_dns_record = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.FileDeleteIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.FileDeleteTable,
			Columns: []string{provisioningscheduledstep.FileDeleteColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(filedelete.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_file_delete = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.FileDownloadIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.FileDownloadTable,
			Columns: []string{provisioningscheduledstep.FileDownloadColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(filedownload.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_file_download = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.FileExtractIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.FileExtractTable,
			Columns: []string{provisioningscheduledstep.FileExtractColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(fileextract.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_file_extract = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.AnsibleIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   provisioningscheduledstep.AnsibleTable,
			Columns: []string{provisioningscheduledstep.AnsibleColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(ansible.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.provisioning_scheduled_step_ansible = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.AgentTasksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   provisioningscheduledstep.AgentTasksTable,
			Columns: []string{provisioningscheduledstep.AgentTasksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(agenttask.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.PlanIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   provisioningscheduledstep.PlanTable,
			Columns: []string{provisioningscheduledstep.PlanColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(plan.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.plan_provisioning_scheduled_step = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := pssc.mutation.GinFileMiddlewareIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2O,
			Inverse: true,
			Table:   provisioningscheduledstep.GinFileMiddlewareTable,
			Columns: []string{provisioningscheduledstep.GinFileMiddlewareColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(ginfilemiddleware.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.gin_file_middleware_provisioning_scheduled_step = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// ProvisioningScheduledStepCreateBulk is the builder for creating many ProvisioningScheduledStep entities in bulk.
type ProvisioningScheduledStepCreateBulk struct {
	config
	builders []*ProvisioningScheduledStepCreate
}

// Save creates the ProvisioningScheduledStep entities in the database.
func (psscb *ProvisioningScheduledStepCreateBulk) Save(ctx context.Context) ([]*ProvisioningScheduledStep, error) {
	specs := make([]*sqlgraph.CreateSpec, len(psscb.builders))
	nodes := make([]*ProvisioningScheduledStep, len(psscb.builders))
	mutators := make([]Mutator, len(psscb.builders))
	for i := range psscb.builders {
		func(i int, root context.Context) {
			builder := psscb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*ProvisioningScheduledStepMutation)
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
					_, err = mutators[i+1].Mutate(root, psscb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, psscb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, psscb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (psscb *ProvisioningScheduledStepCreateBulk) SaveX(ctx context.Context) []*ProvisioningScheduledStep {
	v, err := psscb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (psscb *ProvisioningScheduledStepCreateBulk) Exec(ctx context.Context) error {
	_, err := psscb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (psscb *ProvisioningScheduledStepCreateBulk) ExecX(ctx context.Context) {
	if err := psscb.Exec(ctx); err != nil {
		panic(err)
	}
}
