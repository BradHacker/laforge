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
	"github.com/gen0cide/laforge/ent/finding"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/script"
	"github.com/gen0cide/laforge/ent/user"
	"github.com/google/uuid"
)

// ScriptQuery is the builder for querying Script entities.
type ScriptQuery struct {
	config
	ctx               *QueryContext
	order             []script.OrderOption
	inters            []Interceptor
	predicates        []predicate.Script
	withUsers         *UserQuery
	withFindings      *FindingQuery
	withEnvironment   *EnvironmentQuery
	withFKs           bool
	modifiers         []func(*sql.Selector)
	loadTotal         []func(context.Context, []*Script) error
	withNamedUsers    map[string]*UserQuery
	withNamedFindings map[string]*FindingQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the ScriptQuery builder.
func (sq *ScriptQuery) Where(ps ...predicate.Script) *ScriptQuery {
	sq.predicates = append(sq.predicates, ps...)
	return sq
}

// Limit the number of records to be returned by this query.
func (sq *ScriptQuery) Limit(limit int) *ScriptQuery {
	sq.ctx.Limit = &limit
	return sq
}

// Offset to start from.
func (sq *ScriptQuery) Offset(offset int) *ScriptQuery {
	sq.ctx.Offset = &offset
	return sq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (sq *ScriptQuery) Unique(unique bool) *ScriptQuery {
	sq.ctx.Unique = &unique
	return sq
}

// Order specifies how the records should be ordered.
func (sq *ScriptQuery) Order(o ...script.OrderOption) *ScriptQuery {
	sq.order = append(sq.order, o...)
	return sq
}

// QueryUsers chains the current query on the "Users" edge.
func (sq *ScriptQuery) QueryUsers() *UserQuery {
	query := (&UserClient{config: sq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(script.Table, script.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, script.UsersTable, script.UsersColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryFindings chains the current query on the "Findings" edge.
func (sq *ScriptQuery) QueryFindings() *FindingQuery {
	query := (&FindingClient{config: sq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(script.Table, script.FieldID, selector),
			sqlgraph.To(finding.Table, finding.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, script.FindingsTable, script.FindingsColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryEnvironment chains the current query on the "Environment" edge.
func (sq *ScriptQuery) QueryEnvironment() *EnvironmentQuery {
	query := (&EnvironmentClient{config: sq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(script.Table, script.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, script.EnvironmentTable, script.EnvironmentColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Script entity from the query.
// Returns a *NotFoundError when no Script was found.
func (sq *ScriptQuery) First(ctx context.Context) (*Script, error) {
	nodes, err := sq.Limit(1).All(setContextOp(ctx, sq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{script.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (sq *ScriptQuery) FirstX(ctx context.Context) *Script {
	node, err := sq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Script ID from the query.
// Returns a *NotFoundError when no Script ID was found.
func (sq *ScriptQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = sq.Limit(1).IDs(setContextOp(ctx, sq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{script.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (sq *ScriptQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := sq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Script entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Script entity is found.
// Returns a *NotFoundError when no Script entities are found.
func (sq *ScriptQuery) Only(ctx context.Context) (*Script, error) {
	nodes, err := sq.Limit(2).All(setContextOp(ctx, sq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{script.Label}
	default:
		return nil, &NotSingularError{script.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (sq *ScriptQuery) OnlyX(ctx context.Context) *Script {
	node, err := sq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Script ID in the query.
// Returns a *NotSingularError when more than one Script ID is found.
// Returns a *NotFoundError when no entities are found.
func (sq *ScriptQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = sq.Limit(2).IDs(setContextOp(ctx, sq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{script.Label}
	default:
		err = &NotSingularError{script.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (sq *ScriptQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := sq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Scripts.
func (sq *ScriptQuery) All(ctx context.Context) ([]*Script, error) {
	ctx = setContextOp(ctx, sq.ctx, "All")
	if err := sq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*Script, *ScriptQuery]()
	return withInterceptors[[]*Script](ctx, sq, qr, sq.inters)
}

// AllX is like All, but panics if an error occurs.
func (sq *ScriptQuery) AllX(ctx context.Context) []*Script {
	nodes, err := sq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Script IDs.
func (sq *ScriptQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if sq.ctx.Unique == nil && sq.path != nil {
		sq.Unique(true)
	}
	ctx = setContextOp(ctx, sq.ctx, "IDs")
	if err = sq.Select(script.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (sq *ScriptQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := sq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (sq *ScriptQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, sq.ctx, "Count")
	if err := sq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, sq, querierCount[*ScriptQuery](), sq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (sq *ScriptQuery) CountX(ctx context.Context) int {
	count, err := sq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (sq *ScriptQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, sq.ctx, "Exist")
	switch _, err := sq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (sq *ScriptQuery) ExistX(ctx context.Context) bool {
	exist, err := sq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the ScriptQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (sq *ScriptQuery) Clone() *ScriptQuery {
	if sq == nil {
		return nil
	}
	return &ScriptQuery{
		config:          sq.config,
		ctx:             sq.ctx.Clone(),
		order:           append([]script.OrderOption{}, sq.order...),
		inters:          append([]Interceptor{}, sq.inters...),
		predicates:      append([]predicate.Script{}, sq.predicates...),
		withUsers:       sq.withUsers.Clone(),
		withFindings:    sq.withFindings.Clone(),
		withEnvironment: sq.withEnvironment.Clone(),
		// clone intermediate query.
		sql:  sq.sql.Clone(),
		path: sq.path,
	}
}

// WithUsers tells the query-builder to eager-load the nodes that are connected to
// the "Users" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *ScriptQuery) WithUsers(opts ...func(*UserQuery)) *ScriptQuery {
	query := (&UserClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	sq.withUsers = query
	return sq
}

// WithFindings tells the query-builder to eager-load the nodes that are connected to
// the "Findings" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *ScriptQuery) WithFindings(opts ...func(*FindingQuery)) *ScriptQuery {
	query := (&FindingClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	sq.withFindings = query
	return sq
}

// WithEnvironment tells the query-builder to eager-load the nodes that are connected to
// the "Environment" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *ScriptQuery) WithEnvironment(opts ...func(*EnvironmentQuery)) *ScriptQuery {
	query := (&EnvironmentClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	sq.withEnvironment = query
	return sq
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
//	client.Script.Query().
//		GroupBy(script.FieldHCLID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (sq *ScriptQuery) GroupBy(field string, fields ...string) *ScriptGroupBy {
	sq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &ScriptGroupBy{build: sq}
	grbuild.flds = &sq.ctx.Fields
	grbuild.label = script.Label
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
//	client.Script.Query().
//		Select(script.FieldHCLID).
//		Scan(ctx, &v)
func (sq *ScriptQuery) Select(fields ...string) *ScriptSelect {
	sq.ctx.Fields = append(sq.ctx.Fields, fields...)
	sbuild := &ScriptSelect{ScriptQuery: sq}
	sbuild.label = script.Label
	sbuild.flds, sbuild.scan = &sq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a ScriptSelect configured with the given aggregations.
func (sq *ScriptQuery) Aggregate(fns ...AggregateFunc) *ScriptSelect {
	return sq.Select().Aggregate(fns...)
}

func (sq *ScriptQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range sq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, sq); err != nil {
				return err
			}
		}
	}
	for _, f := range sq.ctx.Fields {
		if !script.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if sq.path != nil {
		prev, err := sq.path(ctx)
		if err != nil {
			return err
		}
		sq.sql = prev
	}
	return nil
}

func (sq *ScriptQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Script, error) {
	var (
		nodes       = []*Script{}
		withFKs     = sq.withFKs
		_spec       = sq.querySpec()
		loadedTypes = [3]bool{
			sq.withUsers != nil,
			sq.withFindings != nil,
			sq.withEnvironment != nil,
		}
	)
	if sq.withEnvironment != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, script.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Script).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Script{config: sq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(sq.modifiers) > 0 {
		_spec.Modifiers = sq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, sq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := sq.withUsers; query != nil {
		if err := sq.loadUsers(ctx, query, nodes,
			func(n *Script) { n.Edges.Users = []*User{} },
			func(n *Script, e *User) { n.Edges.Users = append(n.Edges.Users, e) }); err != nil {
			return nil, err
		}
	}
	if query := sq.withFindings; query != nil {
		if err := sq.loadFindings(ctx, query, nodes,
			func(n *Script) { n.Edges.Findings = []*Finding{} },
			func(n *Script, e *Finding) { n.Edges.Findings = append(n.Edges.Findings, e) }); err != nil {
			return nil, err
		}
	}
	if query := sq.withEnvironment; query != nil {
		if err := sq.loadEnvironment(ctx, query, nodes, nil,
			func(n *Script, e *Environment) { n.Edges.Environment = e }); err != nil {
			return nil, err
		}
	}
	for name, query := range sq.withNamedUsers {
		if err := sq.loadUsers(ctx, query, nodes,
			func(n *Script) { n.appendNamedUsers(name) },
			func(n *Script, e *User) { n.appendNamedUsers(name, e) }); err != nil {
			return nil, err
		}
	}
	for name, query := range sq.withNamedFindings {
		if err := sq.loadFindings(ctx, query, nodes,
			func(n *Script) { n.appendNamedFindings(name) },
			func(n *Script, e *Finding) { n.appendNamedFindings(name, e) }); err != nil {
			return nil, err
		}
	}
	for i := range sq.loadTotal {
		if err := sq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (sq *ScriptQuery) loadUsers(ctx context.Context, query *UserQuery, nodes []*Script, init func(*Script), assign func(*Script, *User)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Script)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.User(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(script.UsersColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.script_users
		if fk == nil {
			return fmt.Errorf(`foreign-key "script_users" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "script_users" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (sq *ScriptQuery) loadFindings(ctx context.Context, query *FindingQuery, nodes []*Script, init func(*Script), assign func(*Script, *Finding)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Script)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.Finding(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(script.FindingsColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.script_findings
		if fk == nil {
			return fmt.Errorf(`foreign-key "script_findings" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "script_findings" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (sq *ScriptQuery) loadEnvironment(ctx context.Context, query *EnvironmentQuery, nodes []*Script, init func(*Script), assign func(*Script, *Environment)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Script)
	for i := range nodes {
		if nodes[i].environment_scripts == nil {
			continue
		}
		fk := *nodes[i].environment_scripts
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
			return fmt.Errorf(`unexpected foreign-key "environment_scripts" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (sq *ScriptQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := sq.querySpec()
	if len(sq.modifiers) > 0 {
		_spec.Modifiers = sq.modifiers
	}
	_spec.Node.Columns = sq.ctx.Fields
	if len(sq.ctx.Fields) > 0 {
		_spec.Unique = sq.ctx.Unique != nil && *sq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, sq.driver, _spec)
}

func (sq *ScriptQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(script.Table, script.Columns, sqlgraph.NewFieldSpec(script.FieldID, field.TypeUUID))
	_spec.From = sq.sql
	if unique := sq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if sq.path != nil {
		_spec.Unique = true
	}
	if fields := sq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, script.FieldID)
		for i := range fields {
			if fields[i] != script.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := sq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := sq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := sq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := sq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (sq *ScriptQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(sq.driver.Dialect())
	t1 := builder.Table(script.Table)
	columns := sq.ctx.Fields
	if len(columns) == 0 {
		columns = script.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if sq.sql != nil {
		selector = sq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if sq.ctx.Unique != nil && *sq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range sq.predicates {
		p(selector)
	}
	for _, p := range sq.order {
		p(selector)
	}
	if offset := sq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := sq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// WithNamedUsers tells the query-builder to eager-load the nodes that are connected to the "Users"
// edge with the given name. The optional arguments are used to configure the query builder of the edge.
func (sq *ScriptQuery) WithNamedUsers(name string, opts ...func(*UserQuery)) *ScriptQuery {
	query := (&UserClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	if sq.withNamedUsers == nil {
		sq.withNamedUsers = make(map[string]*UserQuery)
	}
	sq.withNamedUsers[name] = query
	return sq
}

// WithNamedFindings tells the query-builder to eager-load the nodes that are connected to the "Findings"
// edge with the given name. The optional arguments are used to configure the query builder of the edge.
func (sq *ScriptQuery) WithNamedFindings(name string, opts ...func(*FindingQuery)) *ScriptQuery {
	query := (&FindingClient{config: sq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	if sq.withNamedFindings == nil {
		sq.withNamedFindings = make(map[string]*FindingQuery)
	}
	sq.withNamedFindings[name] = query
	return sq
}

// ScriptGroupBy is the group-by builder for Script entities.
type ScriptGroupBy struct {
	selector
	build *ScriptQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (sgb *ScriptGroupBy) Aggregate(fns ...AggregateFunc) *ScriptGroupBy {
	sgb.fns = append(sgb.fns, fns...)
	return sgb
}

// Scan applies the selector query and scans the result into the given value.
func (sgb *ScriptGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, sgb.build.ctx, "GroupBy")
	if err := sgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ScriptQuery, *ScriptGroupBy](ctx, sgb.build, sgb, sgb.build.inters, v)
}

func (sgb *ScriptGroupBy) sqlScan(ctx context.Context, root *ScriptQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(sgb.fns))
	for _, fn := range sgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*sgb.flds)+len(sgb.fns))
		for _, f := range *sgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*sgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// ScriptSelect is the builder for selecting fields of Script entities.
type ScriptSelect struct {
	*ScriptQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ss *ScriptSelect) Aggregate(fns ...AggregateFunc) *ScriptSelect {
	ss.fns = append(ss.fns, fns...)
	return ss
}

// Scan applies the selector query and scans the result into the given value.
func (ss *ScriptSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ss.ctx, "Select")
	if err := ss.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*ScriptQuery, *ScriptSelect](ctx, ss.ScriptQuery, ss, ss.inters, v)
}

func (ss *ScriptSelect) sqlScan(ctx context.Context, root *ScriptQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ss.fns))
	for _, fn := range ss.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ss.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
