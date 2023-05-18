// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/finding"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/script"
	"github.com/gen0cide/laforge/ent/user"
	"github.com/google/uuid"
)

// FindingCreate is the builder for creating a Finding entity.
type FindingCreate struct {
	config
	mutation *FindingMutation
	hooks    []Hook
}

// SetName sets the "name" field.
func (fc *FindingCreate) SetName(s string) *FindingCreate {
	fc.mutation.SetName(s)
	return fc
}

// SetDescription sets the "description" field.
func (fc *FindingCreate) SetDescription(s string) *FindingCreate {
	fc.mutation.SetDescription(s)
	return fc
}

// SetSeverity sets the "severity" field.
func (fc *FindingCreate) SetSeverity(f finding.Severity) *FindingCreate {
	fc.mutation.SetSeverity(f)
	return fc
}

// SetDifficulty sets the "difficulty" field.
func (fc *FindingCreate) SetDifficulty(f finding.Difficulty) *FindingCreate {
	fc.mutation.SetDifficulty(f)
	return fc
}

// SetTags sets the "tags" field.
func (fc *FindingCreate) SetTags(m map[string]string) *FindingCreate {
	fc.mutation.SetTags(m)
	return fc
}

// SetID sets the "id" field.
func (fc *FindingCreate) SetID(u uuid.UUID) *FindingCreate {
	fc.mutation.SetID(u)
	return fc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (fc *FindingCreate) SetNillableID(u *uuid.UUID) *FindingCreate {
	if u != nil {
		fc.SetID(*u)
	}
	return fc
}

// AddUserIDs adds the "Users" edge to the User entity by IDs.
func (fc *FindingCreate) AddUserIDs(ids ...uuid.UUID) *FindingCreate {
	fc.mutation.AddUserIDs(ids...)
	return fc
}

// AddUsers adds the "Users" edges to the User entity.
func (fc *FindingCreate) AddUsers(u ...*User) *FindingCreate {
	ids := make([]uuid.UUID, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return fc.AddUserIDs(ids...)
}

// SetHostID sets the "Host" edge to the Host entity by ID.
func (fc *FindingCreate) SetHostID(id uuid.UUID) *FindingCreate {
	fc.mutation.SetHostID(id)
	return fc
}

// SetNillableHostID sets the "Host" edge to the Host entity by ID if the given value is not nil.
func (fc *FindingCreate) SetNillableHostID(id *uuid.UUID) *FindingCreate {
	if id != nil {
		fc = fc.SetHostID(*id)
	}
	return fc
}

// SetHost sets the "Host" edge to the Host entity.
func (fc *FindingCreate) SetHost(h *Host) *FindingCreate {
	return fc.SetHostID(h.ID)
}

// SetScriptID sets the "Script" edge to the Script entity by ID.
func (fc *FindingCreate) SetScriptID(id uuid.UUID) *FindingCreate {
	fc.mutation.SetScriptID(id)
	return fc
}

// SetNillableScriptID sets the "Script" edge to the Script entity by ID if the given value is not nil.
func (fc *FindingCreate) SetNillableScriptID(id *uuid.UUID) *FindingCreate {
	if id != nil {
		fc = fc.SetScriptID(*id)
	}
	return fc
}

// SetScript sets the "Script" edge to the Script entity.
func (fc *FindingCreate) SetScript(s *Script) *FindingCreate {
	return fc.SetScriptID(s.ID)
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (fc *FindingCreate) SetEnvironmentID(id uuid.UUID) *FindingCreate {
	fc.mutation.SetEnvironmentID(id)
	return fc
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (fc *FindingCreate) SetNillableEnvironmentID(id *uuid.UUID) *FindingCreate {
	if id != nil {
		fc = fc.SetEnvironmentID(*id)
	}
	return fc
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (fc *FindingCreate) SetEnvironment(e *Environment) *FindingCreate {
	return fc.SetEnvironmentID(e.ID)
}

// Mutation returns the FindingMutation object of the builder.
func (fc *FindingCreate) Mutation() *FindingMutation {
	return fc.mutation
}

// Save creates the Finding in the database.
func (fc *FindingCreate) Save(ctx context.Context) (*Finding, error) {
	fc.defaults()
	return withHooks(ctx, fc.sqlSave, fc.mutation, fc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (fc *FindingCreate) SaveX(ctx context.Context) *Finding {
	v, err := fc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (fc *FindingCreate) Exec(ctx context.Context) error {
	_, err := fc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (fc *FindingCreate) ExecX(ctx context.Context) {
	if err := fc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (fc *FindingCreate) defaults() {
	if _, ok := fc.mutation.ID(); !ok {
		v := finding.DefaultID()
		fc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (fc *FindingCreate) check() error {
	if _, ok := fc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Finding.name"`)}
	}
	if _, ok := fc.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New(`ent: missing required field "Finding.description"`)}
	}
	if _, ok := fc.mutation.Severity(); !ok {
		return &ValidationError{Name: "severity", err: errors.New(`ent: missing required field "Finding.severity"`)}
	}
	if v, ok := fc.mutation.Severity(); ok {
		if err := finding.SeverityValidator(v); err != nil {
			return &ValidationError{Name: "severity", err: fmt.Errorf(`ent: validator failed for field "Finding.severity": %w`, err)}
		}
	}
	if _, ok := fc.mutation.Difficulty(); !ok {
		return &ValidationError{Name: "difficulty", err: errors.New(`ent: missing required field "Finding.difficulty"`)}
	}
	if v, ok := fc.mutation.Difficulty(); ok {
		if err := finding.DifficultyValidator(v); err != nil {
			return &ValidationError{Name: "difficulty", err: fmt.Errorf(`ent: validator failed for field "Finding.difficulty": %w`, err)}
		}
	}
	if _, ok := fc.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New(`ent: missing required field "Finding.tags"`)}
	}
	return nil
}

func (fc *FindingCreate) sqlSave(ctx context.Context) (*Finding, error) {
	if err := fc.check(); err != nil {
		return nil, err
	}
	_node, _spec := fc.createSpec()
	if err := sqlgraph.CreateNode(ctx, fc.driver, _spec); err != nil {
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
	fc.mutation.id = &_node.ID
	fc.mutation.done = true
	return _node, nil
}

func (fc *FindingCreate) createSpec() (*Finding, *sqlgraph.CreateSpec) {
	var (
		_node = &Finding{config: fc.config}
		_spec = sqlgraph.NewCreateSpec(finding.Table, sqlgraph.NewFieldSpec(finding.FieldID, field.TypeUUID))
	)
	if id, ok := fc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := fc.mutation.Name(); ok {
		_spec.SetField(finding.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := fc.mutation.Description(); ok {
		_spec.SetField(finding.FieldDescription, field.TypeString, value)
		_node.Description = value
	}
	if value, ok := fc.mutation.Severity(); ok {
		_spec.SetField(finding.FieldSeverity, field.TypeEnum, value)
		_node.Severity = value
	}
	if value, ok := fc.mutation.Difficulty(); ok {
		_spec.SetField(finding.FieldDifficulty, field.TypeEnum, value)
		_node.Difficulty = value
	}
	if value, ok := fc.mutation.Tags(); ok {
		_spec.SetField(finding.FieldTags, field.TypeJSON, value)
		_node.Tags = value
	}
	if nodes := fc.mutation.UsersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   finding.UsersTable,
			Columns: []string{finding.UsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := fc.mutation.HostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   finding.HostTable,
			Columns: []string{finding.HostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(host.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.finding_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := fc.mutation.ScriptIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   finding.ScriptTable,
			Columns: []string{finding.ScriptColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(script.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.script_findings = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := fc.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   finding.EnvironmentTable,
			Columns: []string{finding.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(environment.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.environment_findings = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// FindingCreateBulk is the builder for creating many Finding entities in bulk.
type FindingCreateBulk struct {
	config
	builders []*FindingCreate
}

// Save creates the Finding entities in the database.
func (fcb *FindingCreateBulk) Save(ctx context.Context) ([]*Finding, error) {
	specs := make([]*sqlgraph.CreateSpec, len(fcb.builders))
	nodes := make([]*Finding, len(fcb.builders))
	mutators := make([]Mutator, len(fcb.builders))
	for i := range fcb.builders {
		func(i int, root context.Context) {
			builder := fcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*FindingMutation)
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
					_, err = mutators[i+1].Mutate(root, fcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, fcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, fcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (fcb *FindingCreateBulk) SaveX(ctx context.Context) []*Finding {
	v, err := fcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (fcb *FindingCreateBulk) Exec(ctx context.Context) error {
	_, err := fcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (fcb *FindingCreateBulk) ExecX(ctx context.Context) {
	if err := fcb.Exec(ctx); err != nil {
		panic(err)
	}
}
