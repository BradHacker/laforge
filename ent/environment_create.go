// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/ansible"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/command"
	"github.com/gen0cide/laforge/ent/competition"
	"github.com/gen0cide/laforge/ent/dns"
	"github.com/gen0cide/laforge/ent/dnsrecord"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/filedelete"
	"github.com/gen0cide/laforge/ent/filedownload"
	"github.com/gen0cide/laforge/ent/fileextract"
	"github.com/gen0cide/laforge/ent/finding"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/hostdependency"
	"github.com/gen0cide/laforge/ent/identity"
	"github.com/gen0cide/laforge/ent/includednetwork"
	"github.com/gen0cide/laforge/ent/network"
	"github.com/gen0cide/laforge/ent/replaypcap"
	"github.com/gen0cide/laforge/ent/repository"
	"github.com/gen0cide/laforge/ent/scheduledstep"
	"github.com/gen0cide/laforge/ent/script"
	"github.com/gen0cide/laforge/ent/servertask"
	"github.com/gen0cide/laforge/ent/user"
	"github.com/gen0cide/laforge/ent/validation"
	"github.com/google/uuid"
)

// EnvironmentCreate is the builder for creating a Environment entity.
type EnvironmentCreate struct {
	config
	mutation *EnvironmentMutation
	hooks    []Hook
}

// SetHclID sets the "hcl_id" field.
func (ec *EnvironmentCreate) SetHclID(s string) *EnvironmentCreate {
	ec.mutation.SetHclID(s)
	return ec
}

// SetCompetitionID sets the "competition_id" field.
func (ec *EnvironmentCreate) SetCompetitionID(s string) *EnvironmentCreate {
	ec.mutation.SetCompetitionID(s)
	return ec
}

// SetName sets the "name" field.
func (ec *EnvironmentCreate) SetName(s string) *EnvironmentCreate {
	ec.mutation.SetName(s)
	return ec
}

// SetDescription sets the "description" field.
func (ec *EnvironmentCreate) SetDescription(s string) *EnvironmentCreate {
	ec.mutation.SetDescription(s)
	return ec
}

// SetBuilder sets the "builder" field.
func (ec *EnvironmentCreate) SetBuilder(s string) *EnvironmentCreate {
	ec.mutation.SetBuilder(s)
	return ec
}

// SetTeamCount sets the "team_count" field.
func (ec *EnvironmentCreate) SetTeamCount(i int) *EnvironmentCreate {
	ec.mutation.SetTeamCount(i)
	return ec
}

// SetRevision sets the "revision" field.
func (ec *EnvironmentCreate) SetRevision(i int) *EnvironmentCreate {
	ec.mutation.SetRevision(i)
	return ec
}

// SetAdminCidrs sets the "admin_cidrs" field.
func (ec *EnvironmentCreate) SetAdminCidrs(s []string) *EnvironmentCreate {
	ec.mutation.SetAdminCidrs(s)
	return ec
}

// SetExposedVdiPorts sets the "exposed_vdi_ports" field.
func (ec *EnvironmentCreate) SetExposedVdiPorts(s []string) *EnvironmentCreate {
	ec.mutation.SetExposedVdiPorts(s)
	return ec
}

// SetConfig sets the "config" field.
func (ec *EnvironmentCreate) SetConfig(m map[string]string) *EnvironmentCreate {
	ec.mutation.SetConfig(m)
	return ec
}

// SetTags sets the "tags" field.
func (ec *EnvironmentCreate) SetTags(m map[string]string) *EnvironmentCreate {
	ec.mutation.SetTags(m)
	return ec
}

// SetID sets the "id" field.
func (ec *EnvironmentCreate) SetID(u uuid.UUID) *EnvironmentCreate {
	ec.mutation.SetID(u)
	return ec
}

// SetNillableID sets the "id" field if the given value is not nil.
func (ec *EnvironmentCreate) SetNillableID(u *uuid.UUID) *EnvironmentCreate {
	if u != nil {
		ec.SetID(*u)
	}
	return ec
}

// AddUserIDs adds the "Users" edge to the User entity by IDs.
func (ec *EnvironmentCreate) AddUserIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddUserIDs(ids...)
	return ec
}

// AddUsers adds the "Users" edges to the User entity.
func (ec *EnvironmentCreate) AddUsers(u ...*User) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return ec.AddUserIDs(ids...)
}

// AddHostIDs adds the "Hosts" edge to the Host entity by IDs.
func (ec *EnvironmentCreate) AddHostIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddHostIDs(ids...)
	return ec
}

// AddHosts adds the "Hosts" edges to the Host entity.
func (ec *EnvironmentCreate) AddHosts(h ...*Host) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(h))
	for i := range h {
		ids[i] = h[i].ID
	}
	return ec.AddHostIDs(ids...)
}

// AddCompetitionIDs adds the "Competitions" edge to the Competition entity by IDs.
func (ec *EnvironmentCreate) AddCompetitionIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddCompetitionIDs(ids...)
	return ec
}

// AddCompetitions adds the "Competitions" edges to the Competition entity.
func (ec *EnvironmentCreate) AddCompetitions(c ...*Competition) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return ec.AddCompetitionIDs(ids...)
}

// AddIdentityIDs adds the "Identities" edge to the Identity entity by IDs.
func (ec *EnvironmentCreate) AddIdentityIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddIdentityIDs(ids...)
	return ec
}

// AddIdentities adds the "Identities" edges to the Identity entity.
func (ec *EnvironmentCreate) AddIdentities(i ...*Identity) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(i))
	for j := range i {
		ids[j] = i[j].ID
	}
	return ec.AddIdentityIDs(ids...)
}

// AddCommandIDs adds the "Commands" edge to the Command entity by IDs.
func (ec *EnvironmentCreate) AddCommandIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddCommandIDs(ids...)
	return ec
}

// AddCommands adds the "Commands" edges to the Command entity.
func (ec *EnvironmentCreate) AddCommands(c ...*Command) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(c))
	for i := range c {
		ids[i] = c[i].ID
	}
	return ec.AddCommandIDs(ids...)
}

// AddScriptIDs adds the "Scripts" edge to the Script entity by IDs.
func (ec *EnvironmentCreate) AddScriptIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddScriptIDs(ids...)
	return ec
}

// AddScripts adds the "Scripts" edges to the Script entity.
func (ec *EnvironmentCreate) AddScripts(s ...*Script) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(s))
	for i := range s {
		ids[i] = s[i].ID
	}
	return ec.AddScriptIDs(ids...)
}

// AddFileDownloadIDs adds the "FileDownloads" edge to the FileDownload entity by IDs.
func (ec *EnvironmentCreate) AddFileDownloadIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddFileDownloadIDs(ids...)
	return ec
}

// AddFileDownloads adds the "FileDownloads" edges to the FileDownload entity.
func (ec *EnvironmentCreate) AddFileDownloads(f ...*FileDownload) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(f))
	for i := range f {
		ids[i] = f[i].ID
	}
	return ec.AddFileDownloadIDs(ids...)
}

// AddFileDeleteIDs adds the "FileDeletes" edge to the FileDelete entity by IDs.
func (ec *EnvironmentCreate) AddFileDeleteIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddFileDeleteIDs(ids...)
	return ec
}

// AddFileDeletes adds the "FileDeletes" edges to the FileDelete entity.
func (ec *EnvironmentCreate) AddFileDeletes(f ...*FileDelete) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(f))
	for i := range f {
		ids[i] = f[i].ID
	}
	return ec.AddFileDeleteIDs(ids...)
}

// AddFileExtractIDs adds the "FileExtracts" edge to the FileExtract entity by IDs.
func (ec *EnvironmentCreate) AddFileExtractIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddFileExtractIDs(ids...)
	return ec
}

// AddFileExtracts adds the "FileExtracts" edges to the FileExtract entity.
func (ec *EnvironmentCreate) AddFileExtracts(f ...*FileExtract) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(f))
	for i := range f {
		ids[i] = f[i].ID
	}
	return ec.AddFileExtractIDs(ids...)
}

// AddIncludedNetworkIDs adds the "IncludedNetworks" edge to the IncludedNetwork entity by IDs.
func (ec *EnvironmentCreate) AddIncludedNetworkIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddIncludedNetworkIDs(ids...)
	return ec
}

// AddIncludedNetworks adds the "IncludedNetworks" edges to the IncludedNetwork entity.
func (ec *EnvironmentCreate) AddIncludedNetworks(i ...*IncludedNetwork) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(i))
	for j := range i {
		ids[j] = i[j].ID
	}
	return ec.AddIncludedNetworkIDs(ids...)
}

// AddFindingIDs adds the "Findings" edge to the Finding entity by IDs.
func (ec *EnvironmentCreate) AddFindingIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddFindingIDs(ids...)
	return ec
}

// AddFindings adds the "Findings" edges to the Finding entity.
func (ec *EnvironmentCreate) AddFindings(f ...*Finding) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(f))
	for i := range f {
		ids[i] = f[i].ID
	}
	return ec.AddFindingIDs(ids...)
}

// AddDNSRecordIDs adds the "DNSRecords" edge to the DNSRecord entity by IDs.
func (ec *EnvironmentCreate) AddDNSRecordIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddDNSRecordIDs(ids...)
	return ec
}

// AddDNSRecords adds the "DNSRecords" edges to the DNSRecord entity.
func (ec *EnvironmentCreate) AddDNSRecords(d ...*DNSRecord) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(d))
	for i := range d {
		ids[i] = d[i].ID
	}
	return ec.AddDNSRecordIDs(ids...)
}

// AddDNSIDs adds the "DNS" edge to the DNS entity by IDs.
func (ec *EnvironmentCreate) AddDNSIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddDNSIDs(ids...)
	return ec
}

// AddDNS adds the "DNS" edges to the DNS entity.
func (ec *EnvironmentCreate) AddDNS(d ...*DNS) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(d))
	for i := range d {
		ids[i] = d[i].ID
	}
	return ec.AddDNSIDs(ids...)
}

// AddNetworkIDs adds the "Networks" edge to the Network entity by IDs.
func (ec *EnvironmentCreate) AddNetworkIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddNetworkIDs(ids...)
	return ec
}

// AddNetworks adds the "Networks" edges to the Network entity.
func (ec *EnvironmentCreate) AddNetworks(n ...*Network) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(n))
	for i := range n {
		ids[i] = n[i].ID
	}
	return ec.AddNetworkIDs(ids...)
}

// AddHostDependencyIDs adds the "HostDependencies" edge to the HostDependency entity by IDs.
func (ec *EnvironmentCreate) AddHostDependencyIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddHostDependencyIDs(ids...)
	return ec
}

// AddHostDependencies adds the "HostDependencies" edges to the HostDependency entity.
func (ec *EnvironmentCreate) AddHostDependencies(h ...*HostDependency) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(h))
	for i := range h {
		ids[i] = h[i].ID
	}
	return ec.AddHostDependencyIDs(ids...)
}

// AddAnsibleIDs adds the "Ansibles" edge to the Ansible entity by IDs.
func (ec *EnvironmentCreate) AddAnsibleIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddAnsibleIDs(ids...)
	return ec
}

// AddAnsibles adds the "Ansibles" edges to the Ansible entity.
func (ec *EnvironmentCreate) AddAnsibles(a ...*Ansible) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return ec.AddAnsibleIDs(ids...)
}

// AddScheduledStepIDs adds the "ScheduledSteps" edge to the ScheduledStep entity by IDs.
func (ec *EnvironmentCreate) AddScheduledStepIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddScheduledStepIDs(ids...)
	return ec
}

// AddScheduledSteps adds the "ScheduledSteps" edges to the ScheduledStep entity.
func (ec *EnvironmentCreate) AddScheduledSteps(s ...*ScheduledStep) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(s))
	for i := range s {
		ids[i] = s[i].ID
	}
	return ec.AddScheduledStepIDs(ids...)
}

// AddBuildIDs adds the "Builds" edge to the Build entity by IDs.
func (ec *EnvironmentCreate) AddBuildIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddBuildIDs(ids...)
	return ec
}

// AddBuilds adds the "Builds" edges to the Build entity.
func (ec *EnvironmentCreate) AddBuilds(b ...*Build) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return ec.AddBuildIDs(ids...)
}

// AddRepositoryIDs adds the "Repositories" edge to the Repository entity by IDs.
func (ec *EnvironmentCreate) AddRepositoryIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddRepositoryIDs(ids...)
	return ec
}

// AddRepositories adds the "Repositories" edges to the Repository entity.
func (ec *EnvironmentCreate) AddRepositories(r ...*Repository) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return ec.AddRepositoryIDs(ids...)
}

// AddServerTaskIDs adds the "ServerTasks" edge to the ServerTask entity by IDs.
func (ec *EnvironmentCreate) AddServerTaskIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddServerTaskIDs(ids...)
	return ec
}

// AddServerTasks adds the "ServerTasks" edges to the ServerTask entity.
func (ec *EnvironmentCreate) AddServerTasks(s ...*ServerTask) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(s))
	for i := range s {
		ids[i] = s[i].ID
	}
	return ec.AddServerTaskIDs(ids...)
}

// AddValidationIDs adds the "Validations" edge to the Validation entity by IDs.
func (ec *EnvironmentCreate) AddValidationIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddValidationIDs(ids...)
	return ec
}

// AddValidations adds the "Validations" edges to the Validation entity.
func (ec *EnvironmentCreate) AddValidations(v ...*Validation) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(v))
	for i := range v {
		ids[i] = v[i].ID
	}
	return ec.AddValidationIDs(ids...)
}

// AddReplayPcapIDs adds the "ReplayPcaps" edge to the ReplayPcap entity by IDs.
func (ec *EnvironmentCreate) AddReplayPcapIDs(ids ...uuid.UUID) *EnvironmentCreate {
	ec.mutation.AddReplayPcapIDs(ids...)
	return ec
}

// AddReplayPcaps adds the "ReplayPcaps" edges to the ReplayPcap entity.
func (ec *EnvironmentCreate) AddReplayPcaps(r ...*ReplayPcap) *EnvironmentCreate {
	ids := make([]uuid.UUID, len(r))
	for i := range r {
		ids[i] = r[i].ID
	}
	return ec.AddReplayPcapIDs(ids...)
}

// Mutation returns the EnvironmentMutation object of the builder.
func (ec *EnvironmentCreate) Mutation() *EnvironmentMutation {
	return ec.mutation
}

// Save creates the Environment in the database.
func (ec *EnvironmentCreate) Save(ctx context.Context) (*Environment, error) {
	var (
		err  error
		node *Environment
	)
	ec.defaults()
	if len(ec.hooks) == 0 {
		if err = ec.check(); err != nil {
			return nil, err
		}
		node, err = ec.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*EnvironmentMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = ec.check(); err != nil {
				return nil, err
			}
			ec.mutation = mutation
			if node, err = ec.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(ec.hooks) - 1; i >= 0; i-- {
			if ec.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = ec.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, ec.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*Environment)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from EnvironmentMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (ec *EnvironmentCreate) SaveX(ctx context.Context) *Environment {
	v, err := ec.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ec *EnvironmentCreate) Exec(ctx context.Context) error {
	_, err := ec.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ec *EnvironmentCreate) ExecX(ctx context.Context) {
	if err := ec.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ec *EnvironmentCreate) defaults() {
	if _, ok := ec.mutation.ID(); !ok {
		v := environment.DefaultID()
		ec.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ec *EnvironmentCreate) check() error {
	if _, ok := ec.mutation.HclID(); !ok {
		return &ValidationError{Name: "hcl_id", err: errors.New(`ent: missing required field "Environment.hcl_id"`)}
	}
	if _, ok := ec.mutation.CompetitionID(); !ok {
		return &ValidationError{Name: "competition_id", err: errors.New(`ent: missing required field "Environment.competition_id"`)}
	}
	if _, ok := ec.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Environment.name"`)}
	}
	if _, ok := ec.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "Environment.description"`)}
	}
	if _, ok := ec.mutation.Builder(); !ok {
		return &ValidationError{Name: "builder", err: errors.New(`ent: missing required field "Environment.builder"`)}
	}
	if _, ok := ec.mutation.TeamCount(); !ok {
		return &ValidationError{Name: "team_count", err: errors.New(`ent: missing required field "Environment.team_count"`)}
	}
	if _, ok := ec.mutation.Revision(); !ok {
		return &ValidationError{Name: "revision", err: errors.New(`ent: missing required field "Environment.revision"`)}
	}
	if _, ok := ec.mutation.AdminCidrs(); !ok {
		return &ValidationError{Name: "admin_cidrs", err: errors.New(`ent: missing required field "Environment.admin_cidrs"`)}
	}
	if _, ok := ec.mutation.ExposedVdiPorts(); !ok {
		return &ValidationError{Name: "exposed_vdi_ports", err: errors.New(`ent: missing required field "Environment.exposed_vdi_ports"`)}
	}
	if _, ok := ec.mutation.Config(); !ok {
		return &ValidationError{Name: "config", err: errors.New(`ent: missing required field "Environment.config"`)}
	}
	if _, ok := ec.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New(`ent: missing required field "Environment.tags"`)}
	}
	return nil
}

func (ec *EnvironmentCreate) sqlSave(ctx context.Context) (*Environment, error) {
	_node, _spec := ec.createSpec()
	if err := sqlgraph.CreateNode(ctx, ec.driver, _spec); err != nil {
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

func (ec *EnvironmentCreate) createSpec() (*Environment, *sqlgraph.CreateSpec) {
	var (
		_node = &Environment{config: ec.config}
		_spec = &sqlgraph.CreateSpec{
			Table: environment.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: environment.FieldID,
			},
		}
	)
	if id, ok := ec.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := ec.mutation.HclID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: environment.FieldHclID,
		})
		_node.HclID = value
	}
	if value, ok := ec.mutation.CompetitionID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: environment.FieldCompetitionID,
		})
		_node.CompetitionID = value
	}
	if value, ok := ec.mutation.Name(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: environment.FieldName,
		})
		_node.Name = value
	}
	if value, ok := ec.mutation.Description(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: environment.FieldDescription,
		})
		_node.Description = value
	}
	if value, ok := ec.mutation.Builder(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: environment.FieldBuilder,
		})
		_node.Builder = value
	}
	if value, ok := ec.mutation.TeamCount(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: environment.FieldTeamCount,
		})
		_node.TeamCount = value
	}
	if value, ok := ec.mutation.Revision(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt,
			Value:  value,
			Column: environment.FieldRevision,
		})
		_node.Revision = value
	}
	if value, ok := ec.mutation.AdminCidrs(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: environment.FieldAdminCidrs,
		})
		_node.AdminCidrs = value
	}
	if value, ok := ec.mutation.ExposedVdiPorts(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: environment.FieldExposedVdiPorts,
		})
		_node.ExposedVdiPorts = value
	}
	if value, ok := ec.mutation.Config(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: environment.FieldConfig,
		})
		_node.Config = value
	}
	if value, ok := ec.mutation.Tags(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: environment.FieldTags,
		})
		_node.Tags = value
	}
	if nodes := ec.mutation.UsersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   environment.UsersTable,
			Columns: environment.UsersPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: user.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.HostsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.HostsTable,
			Columns: []string{environment.HostsColumn},
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
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.CompetitionsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.CompetitionsTable,
			Columns: []string{environment.CompetitionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: competition.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.IdentitiesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.IdentitiesTable,
			Columns: []string{environment.IdentitiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: identity.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.CommandsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.CommandsTable,
			Columns: []string{environment.CommandsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: command.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.ScriptsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.ScriptsTable,
			Columns: []string{environment.ScriptsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: script.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.FileDownloadsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.FileDownloadsTable,
			Columns: []string{environment.FileDownloadsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: filedownload.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.FileDeletesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.FileDeletesTable,
			Columns: []string{environment.FileDeletesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: filedelete.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.FileExtractsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.FileExtractsTable,
			Columns: []string{environment.FileExtractsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: fileextract.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.IncludedNetworksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   environment.IncludedNetworksTable,
			Columns: environment.IncludedNetworksPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: includednetwork.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.FindingsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.FindingsTable,
			Columns: []string{environment.FindingsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: finding.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.DNSRecordsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.DNSRecordsTable,
			Columns: []string{environment.DNSRecordsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: dnsrecord.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.DNSIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   environment.DNSTable,
			Columns: environment.DNSPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: dns.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.NetworksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.NetworksTable,
			Columns: []string{environment.NetworksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: network.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.HostDependenciesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.HostDependenciesTable,
			Columns: []string{environment.HostDependenciesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: hostdependency.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.AnsiblesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.AnsiblesTable,
			Columns: []string{environment.AnsiblesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: ansible.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.ScheduledStepsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.ScheduledStepsTable,
			Columns: []string{environment.ScheduledStepsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: scheduledstep.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.BuildsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   environment.BuildsTable,
			Columns: []string{environment.BuildsColumn},
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
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.RepositoriesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   environment.RepositoriesTable,
			Columns: environment.RepositoriesPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: repository.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.ServerTasksIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   environment.ServerTasksTable,
			Columns: []string{environment.ServerTasksColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: servertask.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.ValidationsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.ValidationsTable,
			Columns: []string{environment.ValidationsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: validation.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ec.mutation.ReplayPcapsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   environment.ReplayPcapsTable,
			Columns: []string{environment.ReplayPcapsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: replaypcap.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// EnvironmentCreateBulk is the builder for creating many Environment entities in bulk.
type EnvironmentCreateBulk struct {
	config
	builders []*EnvironmentCreate
}

// Save creates the Environment entities in the database.
func (ecb *EnvironmentCreateBulk) Save(ctx context.Context) ([]*Environment, error) {
	specs := make([]*sqlgraph.CreateSpec, len(ecb.builders))
	nodes := make([]*Environment, len(ecb.builders))
	mutators := make([]Mutator, len(ecb.builders))
	for i := range ecb.builders {
		func(i int, root context.Context) {
			builder := ecb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*EnvironmentMutation)
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
					_, err = mutators[i+1].Mutate(root, ecb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ecb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, ecb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ecb *EnvironmentCreateBulk) SaveX(ctx context.Context) []*Environment {
	v, err := ecb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ecb *EnvironmentCreateBulk) Exec(ctx context.Context) error {
	_, err := ecb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ecb *EnvironmentCreateBulk) ExecX(ctx context.Context) {
	if err := ecb.Exec(ctx); err != nil {
		panic(err)
	}
}
