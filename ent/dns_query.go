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
	"github.com/gen0cide/laforge/ent/competition"
	"github.com/gen0cide/laforge/ent/dns"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/google/uuid"
)

// DNSQuery is the builder for querying DNS entities.
type DNSQuery struct {
	config
	limit            *int
	offset           *int
	unique           *bool
	order            []OrderFunc
	fields           []string
	predicates       []predicate.DNS
	withEnvironments *EnvironmentQuery
	withCompetitions *CompetitionQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the DNSQuery builder.
func (dq *DNSQuery) Where(ps ...predicate.DNS) *DNSQuery {
	dq.predicates = append(dq.predicates, ps...)
	return dq
}

// Limit adds a limit step to the query.
func (dq *DNSQuery) Limit(limit int) *DNSQuery {
	dq.limit = &limit
	return dq
}

// Offset adds an offset step to the query.
func (dq *DNSQuery) Offset(offset int) *DNSQuery {
	dq.offset = &offset
	return dq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (dq *DNSQuery) Unique(unique bool) *DNSQuery {
	dq.unique = &unique
	return dq
}

// Order adds an order step to the query.
func (dq *DNSQuery) Order(o ...OrderFunc) *DNSQuery {
	dq.order = append(dq.order, o...)
	return dq
}

// QueryEnvironments chains the current query on the "Environments" edge.
func (dq *DNSQuery) QueryEnvironments() *EnvironmentQuery {
	query := &EnvironmentQuery{config: dq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(dns.Table, dns.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, dns.EnvironmentsTable, dns.EnvironmentsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(dq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryCompetitions chains the current query on the "Competitions" edge.
func (dq *DNSQuery) QueryCompetitions() *CompetitionQuery {
	query := &CompetitionQuery{config: dq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := dq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(dns.Table, dns.FieldID, selector),
			sqlgraph.To(competition.Table, competition.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, dns.CompetitionsTable, dns.CompetitionsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(dq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first DNS entity from the query.
// Returns a *NotFoundError when no DNS was found.
func (dq *DNSQuery) First(ctx context.Context) (*DNS, error) {
	nodes, err := dq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{dns.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (dq *DNSQuery) FirstX(ctx context.Context) *DNS {
	node, err := dq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first DNS ID from the query.
// Returns a *NotFoundError when no DNS ID was found.
func (dq *DNSQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = dq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{dns.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (dq *DNSQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := dq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single DNS entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one DNS entity is found.
// Returns a *NotFoundError when no DNS entities are found.
func (dq *DNSQuery) Only(ctx context.Context) (*DNS, error) {
	nodes, err := dq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{dns.Label}
	default:
		return nil, &NotSingularError{dns.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (dq *DNSQuery) OnlyX(ctx context.Context) *DNS {
	node, err := dq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only DNS ID in the query.
// Returns a *NotSingularError when more than one DNS ID is found.
// Returns a *NotFoundError when no entities are found.
func (dq *DNSQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = dq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{dns.Label}
	default:
		err = &NotSingularError{dns.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (dq *DNSQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := dq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of DNSs.
func (dq *DNSQuery) All(ctx context.Context) ([]*DNS, error) {
	if err := dq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return dq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (dq *DNSQuery) AllX(ctx context.Context) []*DNS {
	nodes, err := dq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of DNS IDs.
func (dq *DNSQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := dq.Select(dns.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (dq *DNSQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := dq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (dq *DNSQuery) Count(ctx context.Context) (int, error) {
	if err := dq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return dq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (dq *DNSQuery) CountX(ctx context.Context) int {
	count, err := dq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (dq *DNSQuery) Exist(ctx context.Context) (bool, error) {
	if err := dq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return dq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (dq *DNSQuery) ExistX(ctx context.Context) bool {
	exist, err := dq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the DNSQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (dq *DNSQuery) Clone() *DNSQuery {
	if dq == nil {
		return nil
	}
	return &DNSQuery{
		config:           dq.config,
		limit:            dq.limit,
		offset:           dq.offset,
		order:            append([]OrderFunc{}, dq.order...),
		predicates:       append([]predicate.DNS{}, dq.predicates...),
		withEnvironments: dq.withEnvironments.Clone(),
		withCompetitions: dq.withCompetitions.Clone(),
		// clone intermediate query.
		sql:    dq.sql.Clone(),
		path:   dq.path,
		unique: dq.unique,
	}
}

// WithEnvironments tells the query-builder to eager-load the nodes that are connected to
// the "Environments" edge. The optional arguments are used to configure the query builder of the edge.
func (dq *DNSQuery) WithEnvironments(opts ...func(*EnvironmentQuery)) *DNSQuery {
	query := &EnvironmentQuery{config: dq.config}
	for _, opt := range opts {
		opt(query)
	}
	dq.withEnvironments = query
	return dq
}

// WithCompetitions tells the query-builder to eager-load the nodes that are connected to
// the "Competitions" edge. The optional arguments are used to configure the query builder of the edge.
func (dq *DNSQuery) WithCompetitions(opts ...func(*CompetitionQuery)) *DNSQuery {
	query := &CompetitionQuery{config: dq.config}
	for _, opt := range opts {
		opt(query)
	}
	dq.withCompetitions = query
	return dq
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
//	client.DNS.Query().
//		GroupBy(dns.FieldHclID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (dq *DNSQuery) GroupBy(field string, fields ...string) *DNSGroupBy {
	grbuild := &DNSGroupBy{config: dq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := dq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return dq.sqlQuery(ctx), nil
	}
	grbuild.label = dns.Label
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
//	client.DNS.Query().
//		Select(dns.FieldHclID).
//		Scan(ctx, &v)
func (dq *DNSQuery) Select(fields ...string) *DNSSelect {
	dq.fields = append(dq.fields, fields...)
	selbuild := &DNSSelect{DNSQuery: dq}
	selbuild.label = dns.Label
	selbuild.flds, selbuild.scan = &dq.fields, selbuild.Scan
	return selbuild
}

func (dq *DNSQuery) prepareQuery(ctx context.Context) error {
	for _, f := range dq.fields {
		if !dns.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if dq.path != nil {
		prev, err := dq.path(ctx)
		if err != nil {
			return err
		}
		dq.sql = prev
	}
	return nil
}

func (dq *DNSQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*DNS, error) {
	var (
		nodes       = []*DNS{}
		_spec       = dq.querySpec()
		loadedTypes = [2]bool{
			dq.withEnvironments != nil,
			dq.withCompetitions != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*DNS).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &DNS{config: dq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, dq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := dq.withEnvironments; query != nil {
		if err := dq.loadEnvironments(ctx, query, nodes,
			func(n *DNS) { n.Edges.Environments = []*Environment{} },
			func(n *DNS, e *Environment) { n.Edges.Environments = append(n.Edges.Environments, e) }); err != nil {
			return nil, err
		}
	}
	if query := dq.withCompetitions; query != nil {
		if err := dq.loadCompetitions(ctx, query, nodes,
			func(n *DNS) { n.Edges.Competitions = []*Competition{} },
			func(n *DNS, e *Competition) { n.Edges.Competitions = append(n.Edges.Competitions, e) }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (dq *DNSQuery) loadEnvironments(ctx context.Context, query *EnvironmentQuery, nodes []*DNS, init func(*DNS), assign func(*DNS, *Environment)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[uuid.UUID]*DNS)
	nids := make(map[uuid.UUID]map[*DNS]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(dns.EnvironmentsTable)
		s.Join(joinT).On(s.C(environment.FieldID), joinT.C(dns.EnvironmentsPrimaryKey[0]))
		s.Where(sql.InValues(joinT.C(dns.EnvironmentsPrimaryKey[1]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(dns.EnvironmentsPrimaryKey[1]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	neighbors, err := query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
		assign := spec.Assign
		values := spec.ScanValues
		spec.ScanValues = func(columns []string) ([]interface{}, error) {
			values, err := values(columns[1:])
			if err != nil {
				return nil, err
			}
			return append([]interface{}{new(uuid.UUID)}, values...), nil
		}
		spec.Assign = func(columns []string, values []interface{}) error {
			outValue := *values[0].(*uuid.UUID)
			inValue := *values[1].(*uuid.UUID)
			if nids[inValue] == nil {
				nids[inValue] = map[*DNS]struct{}{byID[outValue]: struct{}{}}
				return assign(columns[1:], values[1:])
			}
			nids[inValue][byID[outValue]] = struct{}{}
			return nil
		}
	})
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "Environments" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}
func (dq *DNSQuery) loadCompetitions(ctx context.Context, query *CompetitionQuery, nodes []*DNS, init func(*DNS), assign func(*DNS, *Competition)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[uuid.UUID]*DNS)
	nids := make(map[uuid.UUID]map[*DNS]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(dns.CompetitionsTable)
		s.Join(joinT).On(s.C(competition.FieldID), joinT.C(dns.CompetitionsPrimaryKey[0]))
		s.Where(sql.InValues(joinT.C(dns.CompetitionsPrimaryKey[1]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(dns.CompetitionsPrimaryKey[1]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	neighbors, err := query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
		assign := spec.Assign
		values := spec.ScanValues
		spec.ScanValues = func(columns []string) ([]interface{}, error) {
			values, err := values(columns[1:])
			if err != nil {
				return nil, err
			}
			return append([]interface{}{new(uuid.UUID)}, values...), nil
		}
		spec.Assign = func(columns []string, values []interface{}) error {
			outValue := *values[0].(*uuid.UUID)
			inValue := *values[1].(*uuid.UUID)
			if nids[inValue] == nil {
				nids[inValue] = map[*DNS]struct{}{byID[outValue]: struct{}{}}
				return assign(columns[1:], values[1:])
			}
			nids[inValue][byID[outValue]] = struct{}{}
			return nil
		}
	})
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "Competitions" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}

func (dq *DNSQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := dq.querySpec()
	_spec.Node.Columns = dq.fields
	if len(dq.fields) > 0 {
		_spec.Unique = dq.unique != nil && *dq.unique
	}
	return sqlgraph.CountNodes(ctx, dq.driver, _spec)
}

func (dq *DNSQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := dq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (dq *DNSQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   dns.Table,
			Columns: dns.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: dns.FieldID,
			},
		},
		From:   dq.sql,
		Unique: true,
	}
	if unique := dq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := dq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, dns.FieldID)
		for i := range fields {
			if fields[i] != dns.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := dq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := dq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := dq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := dq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (dq *DNSQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(dq.driver.Dialect())
	t1 := builder.Table(dns.Table)
	columns := dq.fields
	if len(columns) == 0 {
		columns = dns.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if dq.sql != nil {
		selector = dq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if dq.unique != nil && *dq.unique {
		selector.Distinct()
	}
	for _, p := range dq.predicates {
		p(selector)
	}
	for _, p := range dq.order {
		p(selector)
	}
	if offset := dq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := dq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// DNSGroupBy is the group-by builder for DNS entities.
type DNSGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (dgb *DNSGroupBy) Aggregate(fns ...AggregateFunc) *DNSGroupBy {
	dgb.fns = append(dgb.fns, fns...)
	return dgb
}

// Scan applies the group-by query and scans the result into the given value.
func (dgb *DNSGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := dgb.path(ctx)
	if err != nil {
		return err
	}
	dgb.sql = query
	return dgb.sqlScan(ctx, v)
}

func (dgb *DNSGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range dgb.fields {
		if !dns.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := dgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := dgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (dgb *DNSGroupBy) sqlQuery() *sql.Selector {
	selector := dgb.sql.Select()
	aggregation := make([]string, 0, len(dgb.fns))
	for _, fn := range dgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(dgb.fields)+len(dgb.fns))
		for _, f := range dgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(dgb.fields...)...)
}

// DNSSelect is the builder for selecting fields of DNS entities.
type DNSSelect struct {
	*DNSQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (ds *DNSSelect) Scan(ctx context.Context, v interface{}) error {
	if err := ds.prepareQuery(ctx); err != nil {
		return err
	}
	ds.sql = ds.DNSQuery.sqlQuery(ctx)
	return ds.sqlScan(ctx, v)
}

func (ds *DNSSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := ds.sql.Query()
	if err := ds.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
