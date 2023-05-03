// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/ansible"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/user"
	"github.com/google/uuid"
)

// AnsibleUpdate is the builder for updating Ansible entities.
type AnsibleUpdate struct {
	config
	hooks    []Hook
	mutation *AnsibleMutation
}

// Where appends a list predicates to the AnsibleUpdate builder.
func (au *AnsibleUpdate) Where(ps ...predicate.Ansible) *AnsibleUpdate {
	au.mutation.Where(ps...)
	return au
}

// SetName sets the "name" field.
func (au *AnsibleUpdate) SetName(s string) *AnsibleUpdate {
	au.mutation.SetName(s)
	return au
}

// SetHclID sets the "hcl_id" field.
func (au *AnsibleUpdate) SetHclID(s string) *AnsibleUpdate {
	au.mutation.SetHclID(s)
	return au
}

// SetDescription sets the "description" field.
func (au *AnsibleUpdate) SetDescription(s string) *AnsibleUpdate {
	au.mutation.SetDescription(s)
	return au
}

// SetSource sets the "source" field.
func (au *AnsibleUpdate) SetSource(s string) *AnsibleUpdate {
	au.mutation.SetSource(s)
	return au
}

// SetPlaybookName sets the "playbook_name" field.
func (au *AnsibleUpdate) SetPlaybookName(s string) *AnsibleUpdate {
	au.mutation.SetPlaybookName(s)
	return au
}

// SetMethod sets the "method" field.
func (au *AnsibleUpdate) SetMethod(a ansible.Method) *AnsibleUpdate {
	au.mutation.SetMethod(a)
	return au
}

// SetInventory sets the "inventory" field.
func (au *AnsibleUpdate) SetInventory(s string) *AnsibleUpdate {
	au.mutation.SetInventory(s)
	return au
}

// SetAbsPath sets the "abs_path" field.
func (au *AnsibleUpdate) SetAbsPath(s string) *AnsibleUpdate {
	au.mutation.SetAbsPath(s)
	return au
}

// SetTags sets the "tags" field.
func (au *AnsibleUpdate) SetTags(m map[string]string) *AnsibleUpdate {
	au.mutation.SetTags(m)
	return au
}

// SetValidations sets the "validations" field.
func (au *AnsibleUpdate) SetValidations(s []string) *AnsibleUpdate {
	au.mutation.SetValidations(s)
	return au
}

// AddUserIDs adds the "Users" edge to the User entity by IDs.
func (au *AnsibleUpdate) AddUserIDs(ids ...uuid.UUID) *AnsibleUpdate {
	au.mutation.AddUserIDs(ids...)
	return au
}

// AddUsers adds the "Users" edges to the User entity.
func (au *AnsibleUpdate) AddUsers(u ...*User) *AnsibleUpdate {
	ids := make([]uuid.UUID, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return au.AddUserIDs(ids...)
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (au *AnsibleUpdate) SetEnvironmentID(id uuid.UUID) *AnsibleUpdate {
	au.mutation.SetEnvironmentID(id)
	return au
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (au *AnsibleUpdate) SetNillableEnvironmentID(id *uuid.UUID) *AnsibleUpdate {
	if id != nil {
		au = au.SetEnvironmentID(*id)
	}
	return au
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (au *AnsibleUpdate) SetEnvironment(e *Environment) *AnsibleUpdate {
	return au.SetEnvironmentID(e.ID)
}

// Mutation returns the AnsibleMutation object of the builder.
func (au *AnsibleUpdate) Mutation() *AnsibleMutation {
	return au.mutation
}

// ClearUsers clears all "Users" edges to the User entity.
func (au *AnsibleUpdate) ClearUsers() *AnsibleUpdate {
	au.mutation.ClearUsers()
	return au
}

// RemoveUserIDs removes the "Users" edge to User entities by IDs.
func (au *AnsibleUpdate) RemoveUserIDs(ids ...uuid.UUID) *AnsibleUpdate {
	au.mutation.RemoveUserIDs(ids...)
	return au
}

// RemoveUsers removes "Users" edges to User entities.
func (au *AnsibleUpdate) RemoveUsers(u ...*User) *AnsibleUpdate {
	ids := make([]uuid.UUID, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return au.RemoveUserIDs(ids...)
}

// ClearEnvironment clears the "Environment" edge to the Environment entity.
func (au *AnsibleUpdate) ClearEnvironment() *AnsibleUpdate {
	au.mutation.ClearEnvironment()
	return au
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (au *AnsibleUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(au.hooks) == 0 {
		if err = au.check(); err != nil {
			return 0, err
		}
		affected, err = au.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AnsibleMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = au.check(); err != nil {
				return 0, err
			}
			au.mutation = mutation
			affected, err = au.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(au.hooks) - 1; i >= 0; i-- {
			if au.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = au.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, au.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (au *AnsibleUpdate) SaveX(ctx context.Context) int {
	affected, err := au.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (au *AnsibleUpdate) Exec(ctx context.Context) error {
	_, err := au.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (au *AnsibleUpdate) ExecX(ctx context.Context) {
	if err := au.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (au *AnsibleUpdate) check() error {
	if v, ok := au.mutation.Method(); ok {
		if err := ansible.MethodValidator(v); err != nil {
			return &ValidationError{Name: "method", err: fmt.Errorf(`ent: validator failed for field "Ansible.method": %w`, err)}
		}
	}
	return nil
}

func (au *AnsibleUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   ansible.Table,
			Columns: ansible.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: ansible.FieldID,
			},
		},
	}
	if ps := au.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := au.mutation.Name(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldName,
		})
	}
	if value, ok := au.mutation.HclID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldHclID,
		})
	}
	if value, ok := au.mutation.Description(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldDescription,
		})
	}
	if value, ok := au.mutation.Source(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldSource,
		})
	}
	if value, ok := au.mutation.PlaybookName(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldPlaybookName,
		})
	}
	if value, ok := au.mutation.Method(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: ansible.FieldMethod,
		})
	}
	if value, ok := au.mutation.Inventory(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldInventory,
		})
	}
	if value, ok := au.mutation.AbsPath(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldAbsPath,
		})
	}
	if value, ok := au.mutation.Tags(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: ansible.FieldTags,
		})
	}
	if value, ok := au.mutation.Validations(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: ansible.FieldValidations,
		})
	}
	if au.mutation.UsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   ansible.UsersTable,
			Columns: []string{ansible.UsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: user.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := au.mutation.RemovedUsersIDs(); len(nodes) > 0 && !au.mutation.UsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   ansible.UsersTable,
			Columns: []string{ansible.UsersColumn},
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := au.mutation.UsersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   ansible.UsersTable,
			Columns: []string{ansible.UsersColumn},
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if au.mutation.EnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   ansible.EnvironmentTable,
			Columns: []string{ansible.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := au.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   ansible.EnvironmentTable,
			Columns: []string{ansible.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, au.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{ansible.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// AnsibleUpdateOne is the builder for updating a single Ansible entity.
type AnsibleUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *AnsibleMutation
}

// SetName sets the "name" field.
func (auo *AnsibleUpdateOne) SetName(s string) *AnsibleUpdateOne {
	auo.mutation.SetName(s)
	return auo
}

// SetHclID sets the "hcl_id" field.
func (auo *AnsibleUpdateOne) SetHclID(s string) *AnsibleUpdateOne {
	auo.mutation.SetHclID(s)
	return auo
}

// SetDescription sets the "description" field.
func (auo *AnsibleUpdateOne) SetDescription(s string) *AnsibleUpdateOne {
	auo.mutation.SetDescription(s)
	return auo
}

// SetSource sets the "source" field.
func (auo *AnsibleUpdateOne) SetSource(s string) *AnsibleUpdateOne {
	auo.mutation.SetSource(s)
	return auo
}

// SetPlaybookName sets the "playbook_name" field.
func (auo *AnsibleUpdateOne) SetPlaybookName(s string) *AnsibleUpdateOne {
	auo.mutation.SetPlaybookName(s)
	return auo
}

// SetMethod sets the "method" field.
func (auo *AnsibleUpdateOne) SetMethod(a ansible.Method) *AnsibleUpdateOne {
	auo.mutation.SetMethod(a)
	return auo
}

// SetInventory sets the "inventory" field.
func (auo *AnsibleUpdateOne) SetInventory(s string) *AnsibleUpdateOne {
	auo.mutation.SetInventory(s)
	return auo
}

// SetAbsPath sets the "abs_path" field.
func (auo *AnsibleUpdateOne) SetAbsPath(s string) *AnsibleUpdateOne {
	auo.mutation.SetAbsPath(s)
	return auo
}

// SetTags sets the "tags" field.
func (auo *AnsibleUpdateOne) SetTags(m map[string]string) *AnsibleUpdateOne {
	auo.mutation.SetTags(m)
	return auo
}

// SetValidations sets the "validations" field.
func (auo *AnsibleUpdateOne) SetValidations(s []string) *AnsibleUpdateOne {
	auo.mutation.SetValidations(s)
	return auo
}

// AddUserIDs adds the "Users" edge to the User entity by IDs.
func (auo *AnsibleUpdateOne) AddUserIDs(ids ...uuid.UUID) *AnsibleUpdateOne {
	auo.mutation.AddUserIDs(ids...)
	return auo
}

// AddUsers adds the "Users" edges to the User entity.
func (auo *AnsibleUpdateOne) AddUsers(u ...*User) *AnsibleUpdateOne {
	ids := make([]uuid.UUID, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return auo.AddUserIDs(ids...)
}

// SetEnvironmentID sets the "Environment" edge to the Environment entity by ID.
func (auo *AnsibleUpdateOne) SetEnvironmentID(id uuid.UUID) *AnsibleUpdateOne {
	auo.mutation.SetEnvironmentID(id)
	return auo
}

// SetNillableEnvironmentID sets the "Environment" edge to the Environment entity by ID if the given value is not nil.
func (auo *AnsibleUpdateOne) SetNillableEnvironmentID(id *uuid.UUID) *AnsibleUpdateOne {
	if id != nil {
		auo = auo.SetEnvironmentID(*id)
	}
	return auo
}

// SetEnvironment sets the "Environment" edge to the Environment entity.
func (auo *AnsibleUpdateOne) SetEnvironment(e *Environment) *AnsibleUpdateOne {
	return auo.SetEnvironmentID(e.ID)
}

// Mutation returns the AnsibleMutation object of the builder.
func (auo *AnsibleUpdateOne) Mutation() *AnsibleMutation {
	return auo.mutation
}

// ClearUsers clears all "Users" edges to the User entity.
func (auo *AnsibleUpdateOne) ClearUsers() *AnsibleUpdateOne {
	auo.mutation.ClearUsers()
	return auo
}

// RemoveUserIDs removes the "Users" edge to User entities by IDs.
func (auo *AnsibleUpdateOne) RemoveUserIDs(ids ...uuid.UUID) *AnsibleUpdateOne {
	auo.mutation.RemoveUserIDs(ids...)
	return auo
}

// RemoveUsers removes "Users" edges to User entities.
func (auo *AnsibleUpdateOne) RemoveUsers(u ...*User) *AnsibleUpdateOne {
	ids := make([]uuid.UUID, len(u))
	for i := range u {
		ids[i] = u[i].ID
	}
	return auo.RemoveUserIDs(ids...)
}

// ClearEnvironment clears the "Environment" edge to the Environment entity.
func (auo *AnsibleUpdateOne) ClearEnvironment() *AnsibleUpdateOne {
	auo.mutation.ClearEnvironment()
	return auo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (auo *AnsibleUpdateOne) Select(field string, fields ...string) *AnsibleUpdateOne {
	auo.fields = append([]string{field}, fields...)
	return auo
}

// Save executes the query and returns the updated Ansible entity.
func (auo *AnsibleUpdateOne) Save(ctx context.Context) (*Ansible, error) {
	var (
		err  error
		node *Ansible
	)
	if len(auo.hooks) == 0 {
		if err = auo.check(); err != nil {
			return nil, err
		}
		node, err = auo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AnsibleMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = auo.check(); err != nil {
				return nil, err
			}
			auo.mutation = mutation
			node, err = auo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(auo.hooks) - 1; i >= 0; i-- {
			if auo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = auo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, auo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*Ansible)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from AnsibleMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (auo *AnsibleUpdateOne) SaveX(ctx context.Context) *Ansible {
	node, err := auo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (auo *AnsibleUpdateOne) Exec(ctx context.Context) error {
	_, err := auo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (auo *AnsibleUpdateOne) ExecX(ctx context.Context) {
	if err := auo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (auo *AnsibleUpdateOne) check() error {
	if v, ok := auo.mutation.Method(); ok {
		if err := ansible.MethodValidator(v); err != nil {
			return &ValidationError{Name: "method", err: fmt.Errorf(`ent: validator failed for field "Ansible.method": %w`, err)}
		}
	}
	return nil
}

func (auo *AnsibleUpdateOne) sqlSave(ctx context.Context) (_node *Ansible, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   ansible.Table,
			Columns: ansible.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: ansible.FieldID,
			},
		},
	}
	id, ok := auo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Ansible.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := auo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, ansible.FieldID)
		for _, f := range fields {
			if !ansible.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != ansible.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := auo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := auo.mutation.Name(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldName,
		})
	}
	if value, ok := auo.mutation.HclID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldHclID,
		})
	}
	if value, ok := auo.mutation.Description(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldDescription,
		})
	}
	if value, ok := auo.mutation.Source(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldSource,
		})
	}
	if value, ok := auo.mutation.PlaybookName(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldPlaybookName,
		})
	}
	if value, ok := auo.mutation.Method(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeEnum,
			Value:  value,
			Column: ansible.FieldMethod,
		})
	}
	if value, ok := auo.mutation.Inventory(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldInventory,
		})
	}
	if value, ok := auo.mutation.AbsPath(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: ansible.FieldAbsPath,
		})
	}
	if value, ok := auo.mutation.Tags(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: ansible.FieldTags,
		})
	}
	if value, ok := auo.mutation.Validations(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeJSON,
			Value:  value,
			Column: ansible.FieldValidations,
		})
	}
	if auo.mutation.UsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   ansible.UsersTable,
			Columns: []string{ansible.UsersColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: user.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := auo.mutation.RemovedUsersIDs(); len(nodes) > 0 && !auo.mutation.UsersCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   ansible.UsersTable,
			Columns: []string{ansible.UsersColumn},
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
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := auo.mutation.UsersIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   ansible.UsersTable,
			Columns: []string{ansible.UsersColumn},
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
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if auo.mutation.EnvironmentCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   ansible.EnvironmentTable,
			Columns: []string{ansible.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := auo.mutation.EnvironmentIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   ansible.EnvironmentTable,
			Columns: []string{ansible.EnvironmentColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeUUID,
					Column: environment.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &Ansible{config: auo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, auo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{ansible.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
