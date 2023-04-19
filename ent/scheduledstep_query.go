// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/scheduledstep"
	"github.com/google/uuid"
)

// ScheduledStepQuery is the builder for querying ScheduledStep entities.
type ScheduledStepQuery struct {
	config
	limit                          *int
	offset                         *int
	unique                         *bool
	order                          []OrderFunc
	fields                         []string
	predicates                     []predicate.ScheduledStep
	withScheduledStepToEnvironment *EnvironmentQuery
	withFKs                        bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the ScheduledStepQuery builder.
func (ssq *ScheduledStepQuery) Where(ps ...predicate.ScheduledStep) *ScheduledStepQuery {
	ssq.predicates = append(ssq.predicates, ps...)
	return ssq
}

// Limit adds a limit step to the query.
func (ssq *ScheduledStepQuery) Limit(limit int) *ScheduledStepQuery {
	ssq.limit = &limit
	return ssq
}

// Offset adds an offset step to the query.
func (ssq *ScheduledStepQuery) Offset(offset int) *ScheduledStepQuery {
	ssq.offset = &offset
	return ssq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ssq *ScheduledStepQuery) Unique(unique bool) *ScheduledStepQuery {
	ssq.unique = &unique
	return ssq
}

// Order adds an order step to the query.
func (ssq *ScheduledStepQuery) Order(o ...OrderFunc) *ScheduledStepQuery {
	ssq.order = append(ssq.order, o...)
	return ssq
}

// QueryScheduledStepToEnvironment chains the current query on the "ScheduledStepToEnvironment" edge.
func (ssq *ScheduledStepQuery) QueryScheduledStepToEnvironment() *EnvironmentQuery {
	query := &EnvironmentQuery{config: ssq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ssq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ssq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(scheduledstep.Table, scheduledstep.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, scheduledstep.ScheduledStepToEnvironmentTable, scheduledstep.ScheduledStepToEnvironmentColumn),
		)
		fromU = sqlgraph.SetNeighbors(ssq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first ScheduledStep entity from the query.
// Returns a *NotFoundError when no ScheduledStep was found.
func (ssq *ScheduledStepQuery) First(ctx context.Context) (*ScheduledStep, error) {
	nodes, err := ssq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{scheduledstep.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ssq *ScheduledStepQuery) FirstX(ctx context.Context) *ScheduledStep {
	node, err := ssq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first ScheduledStep ID from the query.
// Returns a *NotFoundError when no ScheduledStep ID was found.
func (ssq *ScheduledStepQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = ssq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{scheduledstep.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ssq *ScheduledStepQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := ssq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single ScheduledStep entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one ScheduledStep entity is found.
// Returns a *NotFoundError when no ScheduledStep entities are found.
func (ssq *ScheduledStepQuery) Only(ctx context.Context) (*ScheduledStep, error) {
	nodes, err := ssq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{scheduledstep.Label}
	default:
		return nil, &NotSingularError{scheduledstep.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ssq *ScheduledStepQuery) OnlyX(ctx context.Context) *ScheduledStep {
	node, err := ssq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only ScheduledStep ID in the query.
// Returns a *NotSingularError when more than one ScheduledStep ID is found.
// Returns a *NotFoundError when no entities are found.
func (ssq *ScheduledStepQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = ssq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{scheduledstep.Label}
	default:
		err = &NotSingularError{scheduledstep.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ssq *ScheduledStepQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := ssq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of ScheduledSteps.
func (ssq *ScheduledStepQuery) All(ctx context.Context) ([]*ScheduledStep, error) {
	if err := ssq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return ssq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (ssq *ScheduledStepQuery) AllX(ctx context.Context) []*ScheduledStep {
	nodes, err := ssq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of ScheduledStep IDs.
func (ssq *ScheduledStepQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := ssq.Select(scheduledstep.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ssq *ScheduledStepQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := ssq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ssq *ScheduledStepQuery) Count(ctx context.Context) (int, error) {
	if err := ssq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return ssq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (ssq *ScheduledStepQuery) CountX(ctx context.Context) int {
	count, err := ssq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ssq *ScheduledStepQuery) Exist(ctx context.Context) (bool, error) {
	if err := ssq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return ssq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (ssq *ScheduledStepQuery) ExistX(ctx context.Context) bool {
	exist, err := ssq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the ScheduledStepQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ssq *ScheduledStepQuery) Clone() *ScheduledStepQuery {
	if ssq == nil {
		return nil
	}
	return &ScheduledStepQuery{
		config:                         ssq.config,
		limit:                          ssq.limit,
		offset:                         ssq.offset,
		order:                          append([]OrderFunc{}, ssq.order...),
		predicates:                     append([]predicate.ScheduledStep{}, ssq.predicates...),
		withScheduledStepToEnvironment: ssq.withScheduledStepToEnvironment.Clone(),
		// clone intermediate query.
		sql:    ssq.sql.Clone(),
		path:   ssq.path,
		unique: ssq.unique,
	}
}

// WithScheduledStepToEnvironment tells the query-builder to eager-load the nodes that are connected to
// the "ScheduledStepToEnvironment" edge. The optional arguments are used to configure the query builder of the edge.
func (ssq *ScheduledStepQuery) WithScheduledStepToEnvironment(opts ...func(*EnvironmentQuery)) *ScheduledStepQuery {
	query := &EnvironmentQuery{config: ssq.config}
	for _, opt := range opts {
		opt(query)
	}
	ssq.withScheduledStepToEnvironment = query
	return ssq
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
//	client.ScheduledStep.Query().
//		GroupBy(scheduledstep.FieldHclID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
//
func (ssq *ScheduledStepQuery) GroupBy(field string, fields ...string) *ScheduledStepGroupBy {
	grbuild := &ScheduledStepGroupBy{config: ssq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := ssq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return ssq.sqlQuery(ctx), nil
	}
	grbuild.label = scheduledstep.Label
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
//	client.ScheduledStep.Query().
//		Select(scheduledstep.FieldHclID).
//		Scan(ctx, &v)
//
func (ssq *ScheduledStepQuery) Select(fields ...string) *ScheduledStepSelect {
	ssq.fields = append(ssq.fields, fields...)
	selbuild := &ScheduledStepSelect{ScheduledStepQuery: ssq}
	selbuild.label = scheduledstep.Label
	selbuild.flds, selbuild.scan = &ssq.fields, selbuild.Scan
	return selbuild
}

func (ssq *ScheduledStepQuery) prepareQuery(ctx context.Context) error {
	for _, f := range ssq.fields {
		if !scheduledstep.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if ssq.path != nil {
		prev, err := ssq.path(ctx)
		if err != nil {
			return err
		}
		ssq.sql = prev
	}
	return nil
}

func (ssq *ScheduledStepQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*ScheduledStep, error) {
	var (
		nodes       = []*ScheduledStep{}
		withFKs     = ssq.withFKs
		_spec       = ssq.querySpec()
		loadedTypes = [1]bool{
			ssq.withScheduledStepToEnvironment != nil,
		}
	)
	if ssq.withScheduledStepToEnvironment != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, scheduledstep.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*ScheduledStep).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &ScheduledStep{config: ssq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, ssq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := ssq.withScheduledStepToEnvironment; query != nil {
		if err := ssq.loadScheduledStepToEnvironment(ctx, query, nodes, nil,
			func(n *ScheduledStep, e *Environment) { n.Edges.ScheduledStepToEnvironment = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ssq *ScheduledStepQuery) loadScheduledStepToEnvironment(ctx context.Context, query *EnvironmentQuery, nodes []*ScheduledStep, init func(*ScheduledStep), assign func(*ScheduledStep, *Environment)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*ScheduledStep)
	for i := range nodes {
		if nodes[i].environment_environment_to_scheduled_step == nil {
			continue
		}
		fk := *nodes[i].environment_environment_to_scheduled_step
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
			return fmt.Errorf(`unexpected foreign-key "environment_environment_to_scheduled_step" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (ssq *ScheduledStepQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ssq.querySpec()
	_spec.Node.Columns = ssq.fields
	if len(ssq.fields) > 0 {
		_spec.Unique = ssq.unique != nil && *ssq.unique
	}
	return sqlgraph.CountNodes(ctx, ssq.driver, _spec)
}

func (ssq *ScheduledStepQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := ssq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (ssq *ScheduledStepQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   scheduledstep.Table,
			Columns: scheduledstep.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: scheduledstep.FieldID,
			},
		},
		From:   ssq.sql,
		Unique: true,
	}
	if unique := ssq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := ssq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, scheduledstep.FieldID)
		for i := range fields {
			if fields[i] != scheduledstep.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := ssq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := ssq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := ssq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := ssq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (ssq *ScheduledStepQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ssq.driver.Dialect())
	t1 := builder.Table(scheduledstep.Table)
	columns := ssq.fields
	if len(columns) == 0 {
		columns = scheduledstep.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if ssq.sql != nil {
		selector = ssq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if ssq.unique != nil && *ssq.unique {
		selector.Distinct()
	}
	for _, p := range ssq.predicates {
		p(selector)
	}
	for _, p := range ssq.order {
		p(selector)
	}
	if offset := ssq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := ssq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ScheduledStepGroupBy is the group-by builder for ScheduledStep entities.
type ScheduledStepGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ssgb *ScheduledStepGroupBy) Aggregate(fns ...AggregateFunc) *ScheduledStepGroupBy {
	ssgb.fns = append(ssgb.fns, fns...)
	return ssgb
}

// Scan applies the group-by query and scans the result into the given value.
func (ssgb *ScheduledStepGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := ssgb.path(ctx)
	if err != nil {
		return err
	}
	ssgb.sql = query
	return ssgb.sqlScan(ctx, v)
}

func (ssgb *ScheduledStepGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range ssgb.fields {
		if !scheduledstep.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := ssgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ssgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (ssgb *ScheduledStepGroupBy) sqlQuery() *sql.Selector {
	selector := ssgb.sql.Select()
	aggregation := make([]string, 0, len(ssgb.fns))
	for _, fn := range ssgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(ssgb.fields)+len(ssgb.fns))
		for _, f := range ssgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(ssgb.fields...)...)
}

// ScheduledStepSelect is the builder for selecting fields of ScheduledStep entities.
type ScheduledStepSelect struct {
	*ScheduledStepQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (sss *ScheduledStepSelect) Scan(ctx context.Context, v interface{}) error {
	if err := sss.prepareQuery(ctx); err != nil {
		return err
	}
	sss.sql = sss.ScheduledStepQuery.sqlQuery(ctx)
	return sss.sqlScan(ctx, v)
}

func (sss *ScheduledStepSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := sss.sql.Query()
	if err := sss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
