// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/dnsrecord"
	"github.com/gen0cide/laforge/ent/environment"
)

// DNSRecordCreate is the builder for creating a DNSRecord entity.
type DNSRecordCreate struct {
	config
	mutation *DNSRecordMutation
	hooks    []Hook
}

// SetHclID sets the "hcl_id" field.
func (drc *DNSRecordCreate) SetHclID(s string) *DNSRecordCreate {
	drc.mutation.SetHclID(s)
	return drc
}

// SetName sets the "name" field.
func (drc *DNSRecordCreate) SetName(s string) *DNSRecordCreate {
	drc.mutation.SetName(s)
	return drc
}

// SetValues sets the "values" field.
func (drc *DNSRecordCreate) SetValues(s []string) *DNSRecordCreate {
	drc.mutation.SetValues(s)
	return drc
}

// SetType sets the "type" field.
func (drc *DNSRecordCreate) SetType(s string) *DNSRecordCreate {
	drc.mutation.SetType(s)
	return drc
}

// SetZone sets the "zone" field.
func (drc *DNSRecordCreate) SetZone(s string) *DNSRecordCreate {
	drc.mutation.SetZone(s)
	return drc
}

// SetVars sets the "vars" field.
func (drc *DNSRecordCreate) SetVars(m map[string]string) *DNSRecordCreate {
	drc.mutation.SetVars(m)
	return drc
}

// SetDisabled sets the "disabled" field.
func (drc *DNSRecordCreate) SetDisabled(b bool) *DNSRecordCreate {
	drc.mutation.SetDisabled(b)
	return drc
}

// SetTags sets the "tags" field.
func (drc *DNSRecordCreate) SetTags(m map[string]string) *DNSRecordCreate {
	drc.mutation.SetTags(m)
	return drc
}

// SetDNSRecordToEnvironmentID sets the "DNSRecordToEnvironment" edge to the Environment entity by ID.
func (drc *DNSRecordCreate) SetDNSRecordToEnvironmentID(id int) *DNSRecordCreate {
	drc.mutation.SetDNSRecordToEnvironmentID(id)
	return drc
}

// SetNillableDNSRecordToEnvironmentID sets the "DNSRecordToEnvironment" edge to the Environment entity by ID if the given value is not nil.
func (drc *DNSRecordCreate) SetNillableDNSRecordToEnvironmentID(id *int) *DNSRecordCreate {
	if id != nil {
		drc = drc.SetDNSRecordToEnvironmentID(*id)
	}
	return drc
}

// SetDNSRecordToEnvironment sets the "DNSRecordToEnvironment" edge to the Environment entity.
func (drc *DNSRecordCreate) SetDNSRecordToEnvironment(e *Environment) *DNSRecordCreate {
	return drc.SetDNSRecordToEnvironmentID(e.ID)
}

// Mutation returns the DNSRecordMutation object of the builder.
func (drc *DNSRecordCreate) Mutation() *DNSRecordMutation {
	return drc.mutation
}

// Save creates the DNSRecord in the database.
func (drc *DNSRecordCreate) Save(ctx context.Context) (*DNSRecord, error) {
	var (
		err  error
		node *DNSRecord
	)
	if len(drc.hooks) == 0 {
		if err = drc.check(); err != nil {
			return nil, err
		}
		node, err = drc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DNSRecordMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = drc.check(); err != nil {
				return nil, err
			}
			drc.mutation = mutation
			node, err = drc.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(drc.hooks) - 1; i >= 0; i-- {
			mut = drc.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, drc.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (drc *DNSRecordCreate) SaveX(ctx context.Context) *DNSRecord {
	v, err := drc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// check runs all checks and user-defined validators on the builder.
func (drc *DNSRecordCreate) check() error {
	if _, ok := drc.mutation.HclID(); !ok {
		return &ValidationError{Name: "hcl_id", err: errors.New("ent: missing required field \"hcl_id\"")}
	}
	if _, ok := drc.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New("ent: missing required field \"name\"")}
	}
	if _, ok := drc.mutation.Values(); !ok {
		return &ValidationError{Name: "values", err: errors.New("ent: missing required field \"values\"")}
	}
	if _, ok := drc.mutation.GetType(); !ok {
		return &ValidationError{Name: "type", err: errors.New("ent: missing required field \"type\"")}
	}
	if _, ok := drc.mutation.Zone(); !ok {
		return &ValidationError{Name: "zone", err: errors.New("ent: missing required field \"zone\"")}
	}
	if _, ok := drc.mutation.Vars(); !ok {
		return &ValidationError{Name: "vars", err: errors.New("ent: missing required field \"vars\"")}
	}
	if _, ok := drc.mutation.Disabled(); !ok {
		return &ValidationError{Name: "disabled", err: errors.New("ent: missing required field \"disabled\"")}
	}
	if _, ok := drc.mutation.Tags(); !ok {
		return &ValidationError{Name: "tags", err: errors.New("ent: missing required field \"tags\"")}
	}
	return nil
}

func (drc *DNSRecordCreate) sqlSave(ctx context.Context) (*DNSRecord, error) {
	_node, _spec := drc.createSpec()
	if err := sqlgraph.CreateNode(ctx, drc.driver, _spec); err != nil {
		if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (drc *DNSRecordCreate) createSpec() (*DNSRecord, *sqlgraph.CreateSpec) {
	var (
		_node = &DNSRecord{config: drc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: dnsrecord.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: dnsrecord.FieldID,
			},
		}
	)
	if value, ok := drc.mutation.HclID(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: dnsrecord.FieldHclID,
		})
		_node.HclID = value
	}
	if value, ok := drc.mutation.Name(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: dnsrecord.FieldName,
		})
		_node.Name = value
	}
	if value, ok := drc.mutation.Values(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: dnsrecord.FieldValues,
		})
		_node.Values = value
	}
	if value, ok := drc.mutation.GetType(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: dnsrecord.FieldType,
		})
		_node.Type = value
	}
	if value, ok := drc.mutation.Zone(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: dnsrecord.FieldZone,
		})
		_node.Zone = value
	}
	if value, ok := drc.mutation.Vars(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: dnsrecord.FieldVars,
		})
		_node.Vars = value
	}
	if value, ok := drc.mutation.Disabled(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: dnsrecord.FieldDisabled,
		})
		_node.Disabled = value
	}
	if value, ok := drc.mutation.Tags(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: dnsrecord.FieldTags,
		})
		_node.Tags = value
	}
	if nodes := drc.mutation.DNSRecordToEnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   dnsrecord.DNSRecordToEnvironmentTable,
			Columns: []string{dnsrecord.DNSRecordToEnvironmentColumn},
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
	return _node, _spec
}

// DNSRecordCreateBulk is the builder for creating many DNSRecord entities in bulk.
type DNSRecordCreateBulk struct {
	config
	builders []*DNSRecordCreate
}

// Save creates the DNSRecord entities in the database.
func (drcb *DNSRecordCreateBulk) Save(ctx context.Context) ([]*DNSRecord, error) {
	specs := make([]*sqlgraph.CreateSpec, len(drcb.builders))
	nodes := make([]*DNSRecord, len(drcb.builders))
	mutators := make([]Mutator, len(drcb.builders))
	for i := range drcb.builders {
		func(i int, root context.Context) {
			builder := drcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*DNSRecordMutation)
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
					_, err = mutators[i+1].Mutate(root, drcb.builders[i+1].mutation)
				} else {
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, drcb.driver, &sqlgraph.BatchCreateSpec{Nodes: specs}); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, drcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (drcb *DNSRecordCreateBulk) SaveX(ctx context.Context) []*DNSRecord {
	v, err := drcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}
