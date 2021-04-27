// Code generated by entc, DO NOT EDIT.

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

// AddFindingToUserIDs adds the "FindingToUser" edge to the User entity by IDs.
func (fc *FindingCreate) AddFindingToUserIDs(ids ...int) *FindingCreate {
	fc.mutation.AddFindingToUserIDs(ids...)
	return fc
}

// AddFindingToUser adds the "FindingToUser" edges to the User entity.
func (fc *FindingCreate) AddFindingToUser(u ...*User) *FindingCreate {
	ids := make([]int, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return fc.AddFindingToUserIDs(ids...)
}

// SetFindingToHostID sets the "FindingToHost" edge to the Host entity by ID.
func (fc *FindingCreate) SetFindingToHostID(id int) *FindingCreate {
	fc.mutation.SetFindingToHostID(id)
	return fc
}

// SetNillableFindingToHostID sets the "FindingToHost" edge to the Host entity by ID if the given value is not nil.
func (fc *FindingCreate) SetNillableFindingToHostID(id *int) *FindingCreate {
	if id != nil {
		fc = fc.SetFindingToHostID(*id)
	}
	return fc
}

// SetFindingToHost sets the "FindingToHost" edge to the Host entity.
func (fc *FindingCreate) SetFindingToHost(h *Host) *FindingCreate {
	return fc.SetFindingToHostID(h.ID)
}

// SetFindingToScriptID sets the "FindingToScript" edge to the Script entity by ID.
func (fc *FindingCreate) SetFindingToScriptID(id int) *FindingCreate {
	fc.mutation.SetFindingToScriptID(id)
	return fc
}

// SetNillableFindingToScriptID sets the "FindingToScript" edge to the Script entity by ID if the given value is not nil.
func (fc *FindingCreate) SetNillableFindingToScriptID(id *int) *FindingCreate {
	if id != nil {
		fc = fc.SetFindingToScriptID(*id)
	}
	return fc
}

// SetFindingToScript sets the "FindingToScript" edge to the Script entity.
func (fc *FindingCreate) SetFindingToScript(s *Script) *FindingCreate {
	return fc.SetFindingToScriptID(s.ID)
}

// SetFindingToEnvironmentID sets the "FindingToEnvironment" edge to the Environment entity by ID.
func (fc *FindingCreate) SetFindingToEnvironmentID(id int) *FindingCreate {
	fc.mutation.SetFindingToEnvironmentID(id)
	return fc
}

// SetNillableFindingToEnvironmentID sets the "FindingToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (fc *FindingCreate) SetNillableFindingToEnvironmentID(id *int) *FindingCreate {
	if id != nil {
		fc = fc.SetFindingToEnvironmentID(*id)
	}
	return fc
}

// SetFindingToEnvironment sets the "FindingToEnvironment" edge to the Environment entity.
func (fc *FindingCreate) SetFindingToEnvironment(e *Environment) *FindingCreate {
	return fc.SetFindingToEnvironmentID(e.ID)
}

// Mutation returns the FindingMutation object of the builder.
func (fc *FindingCreate) Mutation() *FindingMutation {
	return fc.mutation
}

// Save creates the Finding in the database.
func (fc *FindingCreate) Save(ctx context.Context) (*Finding, error) {
	var (
		err  error
		node *Finding
	)
	if len(fc.hooks) == 0 {
		if err = fc.check(); err != nil {
			return nil, err
		}
		node, err = fc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*FindingMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = fc.check(); err != nil {
				return nil, err
			}
			fc.mutation = mutation
			node, err = fc.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(fc.hooks) - 1; i >= 0; i-- {
			mut = fc.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, fc.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (fc *FindingCreate) SaveX(ctx context.Context) *Finding {
	v, err := fc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// check runs all checks and user-defined validators on the builder.
func (fc *FindingCreate) check() error {
	if _, ok := fc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New("ent: missing required field \"name\"")}
	}
	if _, ok := fc.mutation.Description(); !ok {
		return &ValidationError{Name: "description", err: errors.New("ent: missing required field \"description\"")}
	}
	if _, ok := fc.mutation.Severity(); !ok {
		return &ValidationError{Name: "severity", err: errors.New("ent: missing required field \"severity\"")}
	}
	if v, ok := fc.mutation.Severity(); ok {
		if err := finding.SeverityValidator(v); err != nil {
			return &ValidationError{Name: "severity", err: fmt.Errorf("ent: validator failed for field \"severity\": %w", err)}
		}
	}
	if _, ok := fc.mutation.Difficulty(); !ok {
		return &ValidationError{Name: "difficulty", err: errors.New("ent: missing required field \"difficulty\"")}
	}
	if v, ok := fc.mutation.Difficulty(); ok {
		if err := finding.DifficultyValidator(v); err != nil {
			return &ValidationError{Name: "difficulty", err: fmt.Errorf("ent: validator failed for field \"difficulty\": %w", err)}
		}
	}
	if _, ok := fc.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New("ent: missing required field \"tags\"")}
	}
	return nil
}

func (fc *FindingCreate) sqlSave(ctx context.Context) (*Finding, error) {
	_node, _spec := fc.createSpec()
	if err := sqlgraph.CreateNode(ctx, fc.driver, _spec); err != nil {
		if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (fc *FindingCreate) createSpec() (*Finding, *sqlgraph.CreateSpec) {
	var (
		_node = &Finding{config: fc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: finding.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: finding.FieldID,
			},
		}
	)
	if value, ok := fc.mutation.Name(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: finding.FieldName,
		})
		_node.Name = value
	}
	if value, ok := fc.mutation.Description(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: finding.FieldDescription,
		})
		_node.Description = value
	}
	if value, ok := fc.mutation.Severity(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: finding.FieldSeverity,
		})
		_node.Severity = value
	}
	if value, ok := fc.mutation.Difficulty(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: finding.FieldDifficulty,
		})
		_node.Difficulty = value
	}
	if value, ok := fc.mutation.Tags(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: finding.FieldTags,
		})
		_node.Tags = value
	}
	if nodes := fc.mutation.FindingToUserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   finding.FindingToUserTable,
			Columns: []string{finding.FindingToUserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: user.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := fc.mutation.FindingToHostIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   finding.FindingToHostTable,
			Columns: []string{finding.FindingToHostColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: host.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.finding_finding_to_host = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := fc.mutation.FindingToScriptIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   finding.FindingToScriptTable,
			Columns: []string{finding.FindingToScriptColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: script.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.script_script_to_finding = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := fc.mutation.FindingToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   finding.FindingToEnvironmentTable,
			Columns: []string{finding.FindingToEnvironmentColumn},
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
		_node.environment_environment_to_finding = &nodes[0]
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
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*FindingMutation)
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
					_, err = mutators[i+1].Mutate(root, fcb.builders[i+1].mutation)
				} else {
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, fcb.driver, &sqlgraph.BatchCreateSpec{Nodes: specs}); err != nil {
						if cerr, ok := isSQLConstraintError(err); ok {
							err = cerr
						}
					}
				}
				mutation.done = true
				if err != nil {
					return nil, err
				}
				id := specs[i].ID.Value.(int64)
				nodes[i].ID = int(id)
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
