// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/competition"
	"github.com/gen0cide/laforge/ent/dns"
	"github.com/gen0cide/laforge/ent/environment"
)

// CompetitionCreate is the builder for creating a Competition entity.
type CompetitionCreate struct {
	config
	mutation *CompetitionMutation
	hooks    []Hook
}

// SetHclID sets the "hcl_id" field.
func (cc *CompetitionCreate) SetHclID(s string) *CompetitionCreate {
	cc.mutation.SetHclID(s)
	return cc
}

// SetRootPassword sets the "root_password" field.
func (cc *CompetitionCreate) SetRootPassword(s string) *CompetitionCreate {
	cc.mutation.SetRootPassword(s)
	return cc
}

// SetConfig sets the "config" field.
func (cc *CompetitionCreate) SetConfig(m map[string]string) *CompetitionCreate {
	cc.mutation.SetConfig(m)
	return cc
}

// SetTags sets the "tags" field.
func (cc *CompetitionCreate) SetTags(m map[string]string) *CompetitionCreate {
	cc.mutation.SetTags(m)
	return cc
}

// AddCompetitionToDNSIDs adds the "CompetitionToDNS" edge to the DNS entity by IDs.
func (cc *CompetitionCreate) AddCompetitionToDNSIDs(ids ...int) *CompetitionCreate {
	cc.mutation.AddCompetitionToDNSIDs(ids...)
	return cc
}

// AddCompetitionToDNS adds the "CompetitionToDNS" edges to the DNS entity.
func (cc *CompetitionCreate) AddCompetitionToDNS(d ...*DNS) *CompetitionCreate {
	ids := make([]int, len(d))
	for i := range d {
		ids[i] = d[i].ID
	}
	return cc.AddCompetitionToDNSIDs(ids...)
}

// SetCompetitionToEnvironmentID sets the "CompetitionToEnvironment" edge to the Environment entity by ID.
func (cc *CompetitionCreate) SetCompetitionToEnvironmentID(id int) *CompetitionCreate {
	cc.mutation.SetCompetitionToEnvironmentID(id)
	return cc
}

// SetNillableCompetitionToEnvironmentID sets the "CompetitionToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (cc *CompetitionCreate) SetNillableCompetitionToEnvironmentID(id *int) *CompetitionCreate {
	if id != nil {
		cc = cc.SetCompetitionToEnvironmentID(*id)
	}
	return cc
}

// SetCompetitionToEnvironment sets the "CompetitionToEnvironment" edge to the Environment entity.
func (cc *CompetitionCreate) SetCompetitionToEnvironment(e *Environment) *CompetitionCreate {
	return cc.SetCompetitionToEnvironmentID(e.ID)
}

// AddCompetitionToBuildIDs adds the "CompetitionToBuild" edge to the Build entity by IDs.
func (cc *CompetitionCreate) AddCompetitionToBuildIDs(ids ...int) *CompetitionCreate {
	cc.mutation.AddCompetitionToBuildIDs(ids...)
	return cc
}

// AddCompetitionToBuild adds the "CompetitionToBuild" edges to the Build entity.
func (cc *CompetitionCreate) AddCompetitionToBuild(b ...*Build) *CompetitionCreate {
	ids := make([]int, len(b))
	for i := range b {
		ids[i] = b[i].ID
	}
	return cc.AddCompetitionToBuildIDs(ids...)
}

// Mutation returns the CompetitionMutation object of the builder.
func (cc *CompetitionCreate) Mutation() *CompetitionMutation {
	return cc.mutation
}

// Save creates the Competition in the database.
func (cc *CompetitionCreate) Save(ctx context.Context) (*Competition, error) {
	var (
		err  error
		node *Competition
	)
	if len(cc.hooks) == 0 {
		if err = cc.check(); err != nil {
			return nil, err
		}
		node, err = cc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*CompetitionMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = cc.check(); err != nil {
				return nil, err
			}
			cc.mutation = mutation
			node, err = cc.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(cc.hooks) - 1; i >= 0; i-- {
			mut = cc.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, cc.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (cc *CompetitionCreate) SaveX(ctx context.Context) *Competition {
	v, err := cc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// check runs all checks and user-defined validators on the builder.
func (cc *CompetitionCreate) check() error {
	if _, ok := cc.mutation.HclID(); !ok {
		return &ValidationError{Name: "hcl_id", err: errors.New("ent: missing required field \"hcl_id\"")}
	}
	if _, ok := cc.mutation.RootPassword(); !ok {
		return &ValidationError{Name: "root_password", err: errors.New("ent: missing required field \"root_password\"")}
	}
	if _, ok := cc.mutation.Config(); !ok {
		return &ValidationError{Name: "config", err: errors.New("ent: missing required field \"config\"")}
	}
	if _, ok := cc.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New("ent: missing required field \"tags\"")}
	}
	return nil
}

func (cc *CompetitionCreate) sqlSave(ctx context.Context) (*Competition, error) {
	_node, _spec := cc.createSpec()
	if err := sqlgraph.CreateNode(ctx, cc.driver, _spec); err != nil {
		if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (cc *CompetitionCreate) createSpec() (*Competition, *sqlgraph.CreateSpec) {
	var (
		_node = &Competition{config: cc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: competition.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: competition.FieldID,
			},
		}
	)
	if value, ok := cc.mutation.HclID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: competition.FieldHclID,
		})
		_node.HclID = value
	}
	if value, ok := cc.mutation.RootPassword(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: competition.FieldRootPassword,
		})
		_node.RootPassword = value
	}
	if value, ok := cc.mutation.Config(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: competition.FieldConfig,
		})
		_node.Config = value
	}
	if value, ok := cc.mutation.Tags(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: competition.FieldTags,
		})
		_node.Tags = value
	}
	if nodes := cc.mutation.CompetitionToDNSIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: false,
			Table:   competition.CompetitionToDNSTable,
			Columns: competition.CompetitionToDNSPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: dns.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := cc.mutation.CompetitionToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   competition.CompetitionToEnvironmentTable,
			Columns: []string{competition.CompetitionToEnvironmentColumn},
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
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := cc.mutation.CompetitionToBuildIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: true,
			Table:   competition.CompetitionToBuildTable,
			Columns: []string{competition.CompetitionToBuildColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: build.FieldID,
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

// CompetitionCreateBulk is the builder for creating many Competition entities in bulk.
type CompetitionCreateBulk struct {
	config
	builders []*CompetitionCreate
}

// Save creates the Competition entities in the database.
func (ccb *CompetitionCreateBulk) Save(ctx context.Context) ([]*Competition, error) {
	specs := make([]*sqlgraph.CreateSpec, len(ccb.builders))
	nodes := make([]*Competition, len(ccb.builders))
	mutators := make([]Mutator, len(ccb.builders))
	for i := range ccb.builders {
		func(i int, root context.Context) {
			builder := ccb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*CompetitionMutation)
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
					_, err = mutators[i+1].Mutate(root, ccb.builders[i+1].mutation)
				} else {
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ccb.driver, &sqlgraph.BatchCreateSpec{Nodes: specs}); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, ccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ccb *CompetitionCreateBulk) SaveX(ctx context.Context) []*Competition {
	v, err := ccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}
