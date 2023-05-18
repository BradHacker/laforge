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
	"github.com/gen0cide/laforge/ent/identity"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/google/uuid"
)

// IdentityQuery is the builder for querying Identity entities.
type IdentityQuery struct {
	config
	ctx             *QueryContext
	order           []identity.OrderOption
	inters          []Interceptor
	predicates      []predicate.Identity
	withEnvironment *EnvironmentQuery
	withFKs         bool
	modifiers       []func(*sql.Selector)
	loadTotal       []func(context.Context, []*Identity) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the IdentityQuery builder.
func (iq *IdentityQuery) Where(ps ...predicate.Identity) *IdentityQuery {
	iq.predicates = append(iq.predicates, ps...)
	return iq
}

// Limit the number of records to be returned by this query.
func (iq *IdentityQuery) Limit(limit int) *IdentityQuery {
	iq.ctx.Limit = &limit
	return iq
}

// Offset to start from.
func (iq *IdentityQuery) Offset(offset int) *IdentityQuery {
	iq.ctx.Offset = &offset
	return iq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (iq *IdentityQuery) Unique(unique bool) *IdentityQuery {
	iq.ctx.Unique = &unique
	return iq
}

// Order specifies how the records should be ordered.
func (iq *IdentityQuery) Order(o ...identity.OrderOption) *IdentityQuery {
	iq.order = append(iq.order, o...)
	return iq
}

// QueryEnvironment chains the current query on the "Environment" edge.
func (iq *IdentityQuery) QueryEnvironment() *EnvironmentQuery {
	query := (&EnvironmentClient{config: iq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := iq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := iq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(identity.Table, identity.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, identity.EnvironmentTable, identity.EnvironmentColumn),
		)
		fromU = sqlgraph.SetNeighbors(iq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Identity entity from the query.
// Returns a *NotFoundError when no Identity was found.
func (iq *IdentityQuery) First(ctx context.Context) (*Identity, error) {
	nodes, err := iq.Limit(1).All(setContextOp(ctx, iq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{identity.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (iq *IdentityQuery) FirstX(ctx context.Context) *Identity {
	node, err := iq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Identity ID from the query.
// Returns a *NotFoundError when no Identity ID was found.
func (iq *IdentityQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = iq.Limit(1).IDs(setContextOp(ctx, iq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{identity.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (iq *IdentityQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := iq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Identity entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Identity entity is found.
// Returns a *NotFoundError when no Identity entities are found.
func (iq *IdentityQuery) Only(ctx context.Context) (*Identity, error) {
	nodes, err := iq.Limit(2).All(setContextOp(ctx, iq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{identity.Label}
	default:
		return nil, &NotSingularError{identity.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (iq *IdentityQuery) OnlyX(ctx context.Context) *Identity {
	node, err := iq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Identity ID in the query.
// Returns a *NotSingularError when more than one Identity ID is found.
// Returns a *NotFoundError when no entities are found.
func (iq *IdentityQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = iq.Limit(2).IDs(setContextOp(ctx, iq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{identity.Label}
	default:
		err = &NotSingularError{identity.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (iq *IdentityQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := iq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Identities.
func (iq *IdentityQuery) All(ctx context.Context) ([]*Identity, error) {
	ctx = setContextOp(ctx, iq.ctx, "All")
	if err := iq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Identity, *IdentityQuery]()
	return withInterceptors[[]*Identity](ctx, iq, qr, iq.inters)
}

// AllX is like All, but panics if an error occurs.
func (iq *IdentityQuery) AllX(ctx context.Context) []*Identity {
	nodes, err := iq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Identity IDs.
func (iq *IdentityQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if iq.ctx.Unique == nil && iq.path != nil {
		iq.Unique(true)
	}
	ctx = setContextOp(ctx, iq.ctx, "IDs")
	if err = iq.Select(identity.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (iq *IdentityQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := iq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (iq *IdentityQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, iq.ctx, "Count")
	if err := iq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, iq, querierCount[*IdentityQuery](), iq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (iq *IdentityQuery) CountX(ctx context.Context) int {
	count, err := iq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (iq *IdentityQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, iq.ctx, "Exist")
	switch _, err := iq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (iq *IdentityQuery) ExistX(ctx context.Context) bool {
	exist, err := iq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the IdentityQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (iq *IdentityQuery) Clone() *IdentityQuery {
	if iq == nil {
		return nil
	}
	return &IdentityQuery{
		config:          iq.config,
		ctx:             iq.ctx.Clone(),
		order:           append([]identity.OrderOption{}, iq.order...),
		inters:          append([]Interceptor{}, iq.inters...),
		predicates:      append([]predicate.Identity{}, iq.predicates...),
		withEnvironment: iq.withEnvironment.Clone(),
		// clone intermediate query.
		sql:  iq.sql.Clone(),
		path: iq.path,
	}
}

// WithEnvironment tells the query-builder to eager-load the nodes that are connected to
// the "Environment" edge. The optional arguments are used to configure the query builder of the edge.
func (iq *IdentityQuery) WithEnvironment(opts ...func(*EnvironmentQuery)) *IdentityQuery {
	query := (&EnvironmentClient{config: iq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	iq.withEnvironment = query
	return iq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		HCLID string `json:"hcl_id,omitempty" hcl:"id,label"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Identity.Query().
//		GroupBy(identity.FieldHCLID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (iq *IdentityQuery) GroupBy(field string, fields ...string) *IdentityGroupBy {
	iq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &IdentityGroupBy{build: iq}
	grbuild.flds = &iq.ctx.Fields
	grbuild.label = identity.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		HCLID string `json:"hcl_id,omitempty" hcl:"id,label"`
//	}
//
//	client.Identity.Query().
//		Select(identity.FieldHCLID).
//		Scan(ctx, &v)
func (iq *IdentityQuery) Select(fields ...string) *IdentitySelect {
	iq.ctx.Fields = append(iq.ctx.Fields, fields...)
	sbuild := &IdentitySelect{IdentityQuery: iq}
	sbuild.label = identity.Label
	sbuild.flds, sbuild.scan = &iq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a IdentitySelect configured with the given aggregations.
func (iq *IdentityQuery) Aggregate(fns ...AggregateFunc) *IdentitySelect {
	return iq.Select().Aggregate(fns...)
}

func (iq *IdentityQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range iq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, iq); err != nil {
				return err
			}
		}
	}
	for _, f := range iq.ctx.Fields {
		if !identity.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if iq.path != nil {
		prev, err := iq.path(ctx)
		if err != nil {
			return err
		}
		iq.sql = prev
	}
	return nil
}

func (iq *IdentityQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Identity, error) {
	var (
		nodes       = []*Identity{}
		withFKs     = iq.withFKs
		_spec       = iq.querySpec()
		loadedTypes = [1]bool{
			iq.withEnvironment != nil,
		}
	)
	if iq.withEnvironment != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, identity.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Identity).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Identity{config: iq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(iq.modifiers) > 0 {
		_spec.Modifiers = iq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, iq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := iq.withEnvironment; query != nil {
		if err := iq.loadEnvironment(ctx, query, nodes, nil,
			func(n *Identity, e *Environment) { n.Edges.Environment = e }); err != nil {
			return nil, err
		}
	}
	for i := range iq.loadTotal {
		if err := iq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (iq *IdentityQuery) loadEnvironment(ctx context.Context, query *EnvironmentQuery, nodes []*Identity, init func(*Identity), assign func(*Identity, *Environment)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Identity)
	for i := range nodes {
		if nodes[i].environment_identities == nil {
			continue
		}
		fk := *nodes[i].environment_identities
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(environment.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "environment_identities" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (iq *IdentityQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := iq.querySpec()
	if len(iq.modifiers) > 0 {
		_spec.Modifiers = iq.modifiers
	}
	_spec.Node.Columns = iq.ctx.Fields
	if len(iq.ctx.Fields) > 0 {
		_spec.Unique = iq.ctx.Unique != nil && *iq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, iq.driver, _spec)
}

func (iq *IdentityQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(identity.Table, identity.Columns, sqlgraph.NewFieldSpec(identity.FieldID, field.TypeUUID))
	_spec.From = iq.sql
	if unique := iq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if iq.path != nil {
		_spec.Unique = true
	}
	if fields := iq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, identity.FieldID)
		for i := range fields {
			if fields[i] != identity.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := iq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := iq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := iq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := iq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (iq *IdentityQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(iq.driver.Dialect())
	t1 := builder.Table(identity.Table)
	columns := iq.ctx.Fields
	if len(columns) == 0 {
		columns = identity.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if iq.sql != nil {
		selector = iq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if iq.ctx.Unique != nil && *iq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range iq.predicates {
		p(selector)
	}
	for _, p := range iq.order {
		p(selector)
	}
	if offset := iq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := iq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// IdentityGroupBy is the group-by builder for Identity entities.
type IdentityGroupBy struct {
	selector
	build *IdentityQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (igb *IdentityGroupBy) Aggregate(fns ...AggregateFunc) *IdentityGroupBy {
	igb.fns = append(igb.fns, fns...)
	return igb
}

// Scan applies the selector query and scans the result into the given value.
func (igb *IdentityGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, igb.build.ctx, "GroupBy")
	if err := igb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IdentityQuery, *IdentityGroupBy](ctx, igb.build, igb, igb.build.inters, v)
}

func (igb *IdentityGroupBy) sqlScan(ctx context.Context, root *IdentityQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(igb.fns))
	for _, fn := range igb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*igb.flds)+len(igb.fns))
		for _, f := range *igb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*igb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := igb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// IdentitySelect is the builder for selecting fields of Identity entities.
type IdentitySelect struct {
	*IdentityQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (is *IdentitySelect) Aggregate(fns ...AggregateFunc) *IdentitySelect {
	is.fns = append(is.fns, fns...)
	return is
}

// Scan applies the selector query and scans the result into the given value.
func (is *IdentitySelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, is.ctx, "Select")
	if err := is.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*IdentityQuery, *IdentitySelect](ctx, is.IdentityQuery, is, is.inters, v)
}

func (is *IdentitySelect) sqlScan(ctx context.Context, root *IdentityQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(is.fns))
	for _, fn := range is.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*is.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := is.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
