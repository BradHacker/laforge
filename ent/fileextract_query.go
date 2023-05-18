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
	"github.com/gen0cide/laforge/ent/fileextract"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/google/uuid"
)

// FileExtractQuery is the builder for querying FileExtract entities.
type FileExtractQuery struct {
	config
	ctx             *QueryContext
	order           []fileextract.OrderOption
	inters          []Interceptor
	predicates      []predicate.FileExtract
	withEnvironment *EnvironmentQuery
	withFKs         bool
	modifiers       []func(*sql.Selector)
	loadTotal       []func(context.Context, []*FileExtract) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the FileExtractQuery builder.
func (feq *FileExtractQuery) Where(ps ...predicate.FileExtract) *FileExtractQuery {
	feq.predicates = append(feq.predicates, ps...)
	return feq
}

// Limit the number of records to be returned by this query.
func (feq *FileExtractQuery) Limit(limit int) *FileExtractQuery {
	feq.ctx.Limit = &limit
	return feq
}

// Offset to start from.
func (feq *FileExtractQuery) Offset(offset int) *FileExtractQuery {
	feq.ctx.Offset = &offset
	return feq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (feq *FileExtractQuery) Unique(unique bool) *FileExtractQuery {
	feq.ctx.Unique = &unique
	return feq
}

// Order specifies how the records should be ordered.
func (feq *FileExtractQuery) Order(o ...fileextract.OrderOption) *FileExtractQuery {
	feq.order = append(feq.order, o...)
	return feq
}

// QueryEnvironment chains the current query on the "Environment" edge.
func (feq *FileExtractQuery) QueryEnvironment() *EnvironmentQuery {
	query := (&EnvironmentClient{config: feq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := feq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := feq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(fileextract.Table, fileextract.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, fileextract.EnvironmentTable, fileextract.EnvironmentColumn),
		)
		fromU = sqlgraph.SetNeighbors(feq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first FileExtract entity from the query.
// Returns a *NotFoundError when no FileExtract was found.
func (feq *FileExtractQuery) First(ctx context.Context) (*FileExtract, error) {
	nodes, err := feq.Limit(1).All(setContextOp(ctx, feq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{fileextract.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (feq *FileExtractQuery) FirstX(ctx context.Context) *FileExtract {
	node, err := feq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first FileExtract ID from the query.
// Returns a *NotFoundError when no FileExtract ID was found.
func (feq *FileExtractQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = feq.Limit(1).IDs(setContextOp(ctx, feq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{fileextract.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (feq *FileExtractQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := feq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single FileExtract entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one FileExtract entity is found.
// Returns a *NotFoundError when no FileExtract entities are found.
func (feq *FileExtractQuery) Only(ctx context.Context) (*FileExtract, error) {
	nodes, err := feq.Limit(2).All(setContextOp(ctx, feq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{fileextract.Label}
	default:
		return nil, &NotSingularError{fileextract.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (feq *FileExtractQuery) OnlyX(ctx context.Context) *FileExtract {
	node, err := feq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only FileExtract ID in the query.
// Returns a *NotSingularError when more than one FileExtract ID is found.
// Returns a *NotFoundError when no entities are found.
func (feq *FileExtractQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = feq.Limit(2).IDs(setContextOp(ctx, feq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{fileextract.Label}
	default:
		err = &NotSingularError{fileextract.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (feq *FileExtractQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := feq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of FileExtracts.
func (feq *FileExtractQuery) All(ctx context.Context) ([]*FileExtract, error) {
	ctx = setContextOp(ctx, feq.ctx, "All")
	if err := feq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*FileExtract, *FileExtractQuery]()
	return withInterceptors[[]*FileExtract](ctx, feq, qr, feq.inters)
}

// AllX is like All, but panics if an error occurs.
func (feq *FileExtractQuery) AllX(ctx context.Context) []*FileExtract {
	nodes, err := feq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of FileExtract IDs.
func (feq *FileExtractQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if feq.ctx.Unique == nil && feq.path != nil {
		feq.Unique(true)
	}
	ctx = setContextOp(ctx, feq.ctx, "IDs")
	if err = feq.Select(fileextract.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (feq *FileExtractQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := feq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (feq *FileExtractQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, feq.ctx, "Count")
	if err := feq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, feq, querierCount[*FileExtractQuery](), feq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (feq *FileExtractQuery) CountX(ctx context.Context) int {
	count, err := feq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (feq *FileExtractQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, feq.ctx, "Exist")
	switch _, err := feq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (feq *FileExtractQuery) ExistX(ctx context.Context) bool {
	exist, err := feq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the FileExtractQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (feq *FileExtractQuery) Clone() *FileExtractQuery {
	if feq == nil {
		return nil
	}
	return &FileExtractQuery{
		config:          feq.config,
		ctx:             feq.ctx.Clone(),
		order:           append([]fileextract.OrderOption{}, feq.order...),
		inters:          append([]Interceptor{}, feq.inters...),
		predicates:      append([]predicate.FileExtract{}, feq.predicates...),
		withEnvironment: feq.withEnvironment.Clone(),
		// clone intermediate query.
		sql:  feq.sql.Clone(),
		path: feq.path,
	}
}

// WithEnvironment tells the query-builder to eager-load the nodes that are connected to
// the "Environment" edge. The optional arguments are used to configure the query builder of the edge.
func (feq *FileExtractQuery) WithEnvironment(opts ...func(*EnvironmentQuery)) *FileExtractQuery {
	query := (&EnvironmentClient{config: feq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	feq.withEnvironment = query
	return feq
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
//	client.FileExtract.Query().
//		GroupBy(fileextract.FieldHCLID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (feq *FileExtractQuery) GroupBy(field string, fields ...string) *FileExtractGroupBy {
	feq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &FileExtractGroupBy{build: feq}
	grbuild.flds = &feq.ctx.Fields
	grbuild.label = fileextract.Label
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
//	client.FileExtract.Query().
//		Select(fileextract.FieldHCLID).
//		Scan(ctx, &v)
func (feq *FileExtractQuery) Select(fields ...string) *FileExtractSelect {
	feq.ctx.Fields = append(feq.ctx.Fields, fields...)
	sbuild := &FileExtractSelect{FileExtractQuery: feq}
	sbuild.label = fileextract.Label
	sbuild.flds, sbuild.scan = &feq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a FileExtractSelect configured with the given aggregations.
func (feq *FileExtractQuery) Aggregate(fns ...AggregateFunc) *FileExtractSelect {
	return feq.Select().Aggregate(fns...)
}

func (feq *FileExtractQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range feq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, feq); err != nil {
				return err
			}
		}
	}
	for _, f := range feq.ctx.Fields {
		if !fileextract.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if feq.path != nil {
		prev, err := feq.path(ctx)
		if err != nil {
			return err
		}
		feq.sql = prev
	}
	return nil
}

func (feq *FileExtractQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*FileExtract, error) {
	var (
		nodes       = []*FileExtract{}
		withFKs     = feq.withFKs
		_spec       = feq.querySpec()
		loadedTypes = [1]bool{
			feq.withEnvironment != nil,
		}
	)
	if feq.withEnvironment != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, fileextract.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*FileExtract).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &FileExtract{config: feq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(feq.modifiers) > 0 {
		_spec.Modifiers = feq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, feq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := feq.withEnvironment; query != nil {
		if err := feq.loadEnvironment(ctx, query, nodes, nil,
			func(n *FileExtract, e *Environment) { n.Edges.Environment = e }); err != nil {
			return nil, err
		}
	}
	for i := range feq.loadTotal {
		if err := feq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (feq *FileExtractQuery) loadEnvironment(ctx context.Context, query *EnvironmentQuery, nodes []*FileExtract, init func(*FileExtract), assign func(*FileExtract, *Environment)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*FileExtract)
	for i := range nodes {
		if nodes[i].environment_file_extracts == nil {
			continue
		}
		fk := *nodes[i].environment_file_extracts
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
			return fmt.Errorf(`unexpected foreign-key "environment_file_extracts" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (feq *FileExtractQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := feq.querySpec()
	if len(feq.modifiers) > 0 {
		_spec.Modifiers = feq.modifiers
	}
	_spec.Node.Columns = feq.ctx.Fields
	if len(feq.ctx.Fields) > 0 {
		_spec.Unique = feq.ctx.Unique != nil && *feq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, feq.driver, _spec)
}

func (feq *FileExtractQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(fileextract.Table, fileextract.Columns, sqlgraph.NewFieldSpec(fileextract.FieldID, field.TypeUUID))
	_spec.From = feq.sql
	if unique := feq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if feq.path != nil {
		_spec.Unique = true
	}
	if fields := feq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, fileextract.FieldID)
		for i := range fields {
			if fields[i] != fileextract.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := feq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := feq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := feq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := feq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (feq *FileExtractQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(feq.driver.Dialect())
	t1 := builder.Table(fileextract.Table)
	columns := feq.ctx.Fields
	if len(columns) == 0 {
		columns = fileextract.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if feq.sql != nil {
		selector = feq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if feq.ctx.Unique != nil && *feq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range feq.predicates {
		p(selector)
	}
	for _, p := range feq.order {
		p(selector)
	}
	if offset := feq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := feq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// FileExtractGroupBy is the group-by builder for FileExtract entities.
type FileExtractGroupBy struct {
	selector
	build *FileExtractQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (fegb *FileExtractGroupBy) Aggregate(fns ...AggregateFunc) *FileExtractGroupBy {
	fegb.fns = append(fegb.fns, fns...)
	return fegb
}

// Scan applies the selector query and scans the result into the given value.
func (fegb *FileExtractGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, fegb.build.ctx, "GroupBy")
	if err := fegb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*FileExtractQuery, *FileExtractGroupBy](ctx, fegb.build, fegb, fegb.build.inters, v)
}

func (fegb *FileExtractGroupBy) sqlScan(ctx context.Context, root *FileExtractQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(fegb.fns))
	for _, fn := range fegb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*fegb.flds)+len(fegb.fns))
		for _, f := range *fegb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*fegb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := fegb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// FileExtractSelect is the builder for selecting fields of FileExtract entities.
type FileExtractSelect struct {
	*FileExtractQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (fes *FileExtractSelect) Aggregate(fns ...AggregateFunc) *FileExtractSelect {
	fes.fns = append(fes.fns, fns...)
	return fes
}

// Scan applies the selector query and scans the result into the given value.
func (fes *FileExtractSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, fes.ctx, "Select")
	if err := fes.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*FileExtractQuery, *FileExtractSelect](ctx, fes.FileExtractQuery, fes, fes.inters, v)
}

func (fes *FileExtractSelect) sqlScan(ctx context.Context, root *FileExtractQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(fes.fns))
	for _, fn := range fes.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*fes.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := fes.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
