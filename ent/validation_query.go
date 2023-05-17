// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/user"
	"github.com/gen0cide/laforge/ent/validation"
	"github.com/google/uuid"
)

// ValidationQuery is the builder for querying Validation entities.
type ValidationQuery struct {
	config
	limit           *int
	offset          *int
	unique          *bool
	order           []OrderFunc
	fields          []string
	predicates      []predicate.Validation
	withUsers       *UserQuery
	withEnvironment *EnvironmentQuery
	withFKs         bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the ValidationQuery builder.
func (vq *ValidationQuery) Where(ps ...predicate.Validation) *ValidationQuery {
	vq.predicates = append(vq.predicates, ps...)
	return vq
}

// Limit adds a limit step to the query.
func (vq *ValidationQuery) Limit(limit int) *ValidationQuery {
	vq.limit = &limit
	return vq
}

// Offset adds an offset step to the query.
func (vq *ValidationQuery) Offset(offset int) *ValidationQuery {
	vq.offset = &offset
	return vq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (vq *ValidationQuery) Unique(unique bool) *ValidationQuery {
	vq.unique = &unique
	return vq
}

// Order adds an order step to the query.
func (vq *ValidationQuery) Order(o ...OrderFunc) *ValidationQuery {
	vq.order = append(vq.order, o...)
	return vq
}

// QueryUsers chains the current query on the "Users" edge.
func (vq *ValidationQuery) QueryUsers() *UserQuery {
	query := &UserQuery{config: vq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := vq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := vq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(validation.Table, validation.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, validation.UsersTable, validation.UsersColumn),
		)
		fromU = sqlgraph.SetNeighbors(vq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryEnvironment chains the current query on the "Environment" edge.
func (vq *ValidationQuery) QueryEnvironment() *EnvironmentQuery {
	query := &EnvironmentQuery{config: vq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := vq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := vq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(validation.Table, validation.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, validation.EnvironmentTable, validation.EnvironmentColumn),
		)
		fromU = sqlgraph.SetNeighbors(vq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Validation entity from the query.
// Returns a *NotFoundError when no Validation was found.
func (vq *ValidationQuery) First(ctx context.Context) (*Validation, error) {
	nodes, err := vq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{validation.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (vq *ValidationQuery) FirstX(ctx context.Context) *Validation {
	node, err := vq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Validation ID from the query.
// Returns a *NotFoundError when no Validation ID was found.
func (vq *ValidationQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = vq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{validation.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (vq *ValidationQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := vq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Validation entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Validation entity is found.
// Returns a *NotFoundError when no Validation entities are found.
func (vq *ValidationQuery) Only(ctx context.Context) (*Validation, error) {
	nodes, err := vq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{validation.Label}
	default:
		return nil, &NotSingularError{validation.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (vq *ValidationQuery) OnlyX(ctx context.Context) *Validation {
	node, err := vq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Validation ID in the query.
// Returns a *NotSingularError when more than one Validation ID is found.
// Returns a *NotFoundError when no entities are found.
func (vq *ValidationQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = vq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{validation.Label}
	default:
		err = &NotSingularError{validation.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (vq *ValidationQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := vq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Validations.
func (vq *ValidationQuery) All(ctx context.Context) ([]*Validation, error) {
	if err := vq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return vq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (vq *ValidationQuery) AllX(ctx context.Context) []*Validation {
	nodes, err := vq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Validation IDs.
func (vq *ValidationQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := vq.Select(validation.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (vq *ValidationQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := vq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (vq *ValidationQuery) Count(ctx context.Context) (int, error) {
	if err := vq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return vq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (vq *ValidationQuery) CountX(ctx context.Context) int {
	count, err := vq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (vq *ValidationQuery) Exist(ctx context.Context) (bool, error) {
	if err := vq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return vq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (vq *ValidationQuery) ExistX(ctx context.Context) bool {
	exist, err := vq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the ValidationQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (vq *ValidationQuery) Clone() *ValidationQuery {
	if vq == nil {
		return nil
	}
	return &ValidationQuery{
		config:          vq.config,
		limit:           vq.limit,
		offset:          vq.offset,
		order:           append([]OrderFunc{}, vq.order...),
		predicates:      append([]predicate.Validation{}, vq.predicates...),
		withUsers:       vq.withUsers.Clone(),
		withEnvironment: vq.withEnvironment.Clone(),
		// clone intermediate query.
		sql:    vq.sql.Clone(),
		path:   vq.path,
		unique: vq.unique,
	}
}

// WithUsers tells the query-builder to eager-load the nodes that are connected to
// the "Users" edge. The optional arguments are used to configure the query builder of the edge.
func (vq *ValidationQuery) WithUsers(opts ...func(*UserQuery)) *ValidationQuery {
	query := &UserQuery{config: vq.config}
	for _, opt := range opts {
		opt(query)
	}
	vq.withUsers = query
	return vq
}

// WithEnvironment tells the query-builder to eager-load the nodes that are connected to
// the "Environment" edge. The optional arguments are used to configure the query builder of the edge.
func (vq *ValidationQuery) WithEnvironment(opts ...func(*EnvironmentQuery)) *ValidationQuery {
	query := &EnvironmentQuery{config: vq.config}
	for _, opt := range opts {
		opt(query)
	}
	vq.withEnvironment = query
	return vq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		HclID string `json:"hcl_id,omitempty" hcl:"id,label"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Validation.Query().
//		GroupBy(validation.FieldHclID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (vq *ValidationQuery) GroupBy(field string, fields ...string) *ValidationGroupBy {
	grbuild := &ValidationGroupBy{config: vq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := vq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return vq.sqlQuery(ctx), nil
	}
	grbuild.label = validation.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		HclID string `json:"hcl_id,omitempty" hcl:"id,label"`
//	}
//
//	client.Validation.Query().
//		Select(validation.FieldHclID).
//		Scan(ctx, &v)
func (vq *ValidationQuery) Select(fields ...string) *ValidationSelect {
	vq.fields = append(vq.fields, fields...)
	selbuild := &ValidationSelect{ValidationQuery: vq}
	selbuild.label = validation.Label
	selbuild.flds, selbuild.scan = &vq.fields, selbuild.Scan
	return selbuild
}

func (vq *ValidationQuery) prepareQuery(ctx context.Context) error {
	for _, f := range vq.fields {
		if !validation.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if vq.path != nil {
		prev, err := vq.path(ctx)
		if err != nil {
			return err
		}
		vq.sql = prev
	}
	return nil
}

func (vq *ValidationQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Validation, error) {
	var (
		nodes       = []*Validation{}
		withFKs     = vq.withFKs
		_spec       = vq.querySpec()
		loadedTypes = [2]bool{
			vq.withUsers != nil,
			vq.withEnvironment != nil,
		}
	)
	if vq.withEnvironment != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, validation.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*Validation).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &Validation{config: vq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, vq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := vq.withUsers; query != nil {
		if err := vq.loadUsers(ctx, query, nodes,
			func(n *Validation) { n.Edges.Users = []*User{} },
			func(n *Validation, e *User) { n.Edges.Users = append(n.Edges.Users, e) }); err != nil {
			return nil, err
		}
	}
	if query := vq.withEnvironment; query != nil {
		if err := vq.loadEnvironment(ctx, query, nodes, nil,
			func(n *Validation, e *Environment) { n.Edges.Environment = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (vq *ValidationQuery) loadUsers(ctx context.Context, query *UserQuery, nodes []*Validation, init func(*Validation), assign func(*Validation, *User)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Validation)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.User(func(s *sql.Selector) {
		s.Where(sql.InValues(validation.UsersColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.validation_users
		if fk == nil {
			return fmt.Errorf(`foreign-key "validation_users" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "validation_users" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (vq *ValidationQuery) loadEnvironment(ctx context.Context, query *EnvironmentQuery, nodes []*Validation, init func(*Validation), assign func(*Validation, *Environment)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Validation)
	for i := range nodes {
		if nodes[i].environment_validations == nil {
			continue
		}
		fk := *nodes[i].environment_validations
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(environment.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "environment_validations" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (vq *ValidationQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := vq.querySpec()
	_spec.Node.Columns = vq.fields
	if len(vq.fields) > 0 {
		_spec.Unique = vq.unique != nil && *vq.unique
	}
	return sqlgraph.CountNodes(ctx, vq.driver, _spec)
}

func (vq *ValidationQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := vq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (vq *ValidationQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   validation.Table,
			Columns: validation.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: validation.FieldID,
			},
		},
		From:   vq.sql,
		Unique: true,
	}
	if unique := vq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := vq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, validation.FieldID)
		for i := range fields {
			if fields[i] != validation.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := vq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := vq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := vq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := vq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (vq *ValidationQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(vq.driver.Dialect())
	t1 := builder.Table(validation.Table)
	columns := vq.fields
	if len(columns) == 0 {
		columns = validation.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if vq.sql != nil {
		selector = vq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if vq.unique != nil && *vq.unique {
		selector.Distinct()
	}
	for _, p := range vq.predicates {
		p(selector)
	}
	for _, p := range vq.order {
		p(selector)
	}
	if offset := vq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := vq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ValidationGroupBy is the group-by builder for Validation entities.
type ValidationGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (vgb *ValidationGroupBy) Aggregate(fns ...AggregateFunc) *ValidationGroupBy {
	vgb.fns = append(vgb.fns, fns...)
	return vgb
}

// Scan applies the group-by query and scans the result into the given value.
func (vgb *ValidationGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := vgb.path(ctx)
	if err != nil {
		return err
	}
	vgb.sql = query
	return vgb.sqlScan(ctx, v)
}

func (vgb *ValidationGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range vgb.fields {
		if !validation.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := vgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := vgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (vgb *ValidationGroupBy) sqlQuery() *sql.Selector {
	selector := vgb.sql.Select()
	aggregation := make([]string, 0, len(vgb.fns))
	for _, fn := range vgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(vgb.fields)+len(vgb.fns))
		for _, f := range vgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(vgb.fields...)...)
}

// ValidationSelect is the builder for selecting fields of Validation entities.
type ValidationSelect struct {
	*ValidationQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (vs *ValidationSelect) Scan(ctx context.Context, v interface{}) error {
	if err := vs.prepareQuery(ctx); err != nil {
		return err
	}
	vs.sql = vs.ValidationQuery.sqlQuery(ctx)
	return vs.sqlScan(ctx, v)
}

func (vs *ValidationSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := vs.sql.Query()
	if err := vs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
