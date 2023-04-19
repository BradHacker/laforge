// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/agentstatus"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/google/uuid"
)

// AgentStatusQuery is the builder for querying AgentStatus entities.
type AgentStatusQuery struct {
	config
	limit                               *int
	offset                              *int
	unique                              *bool
	order                               []OrderFunc
	fields                              []string
	predicates                          []predicate.AgentStatus
	withAgentStatusToProvisionedHost    *ProvisionedHostQuery
	withAgentStatusToProvisionedNetwork *ProvisionedNetworkQuery
	withAgentStatusToBuild              *BuildQuery
	withFKs                             bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AgentStatusQuery builder.
func (asq *AgentStatusQuery) Where(ps ...predicate.AgentStatus) *AgentStatusQuery {
	asq.predicates = append(asq.predicates, ps...)
	return asq
}

// Limit adds a limit step to the query.
func (asq *AgentStatusQuery) Limit(limit int) *AgentStatusQuery {
	asq.limit = &limit
	return asq
}

// Offset adds an offset step to the query.
func (asq *AgentStatusQuery) Offset(offset int) *AgentStatusQuery {
	asq.offset = &offset
	return asq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (asq *AgentStatusQuery) Unique(unique bool) *AgentStatusQuery {
	asq.unique = &unique
	return asq
}

// Order adds an order step to the query.
func (asq *AgentStatusQuery) Order(o ...OrderFunc) *AgentStatusQuery {
	asq.order = append(asq.order, o...)
	return asq
}

// QueryAgentStatusToProvisionedHost chains the current query on the "AgentStatusToProvisionedHost" edge.
func (asq *AgentStatusQuery) QueryAgentStatusToProvisionedHost() *ProvisionedHostQuery {
	query := &ProvisionedHostQuery{config: asq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := asq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := asq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agentstatus.Table, agentstatus.FieldID, selector),
			sqlgraph.To(provisionedhost.Table, provisionedhost.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, agentstatus.AgentStatusToProvisionedHostTable, agentstatus.AgentStatusToProvisionedHostColumn),
		)
		fromU = sqlgraph.SetNeighbors(asq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAgentStatusToProvisionedNetwork chains the current query on the "AgentStatusToProvisionedNetwork" edge.
func (asq *AgentStatusQuery) QueryAgentStatusToProvisionedNetwork() *ProvisionedNetworkQuery {
	query := &ProvisionedNetworkQuery{config: asq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := asq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := asq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agentstatus.Table, agentstatus.FieldID, selector),
			sqlgraph.To(provisionednetwork.Table, provisionednetwork.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, agentstatus.AgentStatusToProvisionedNetworkTable, agentstatus.AgentStatusToProvisionedNetworkColumn),
		)
		fromU = sqlgraph.SetNeighbors(asq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAgentStatusToBuild chains the current query on the "AgentStatusToBuild" edge.
func (asq *AgentStatusQuery) QueryAgentStatusToBuild() *BuildQuery {
	query := &BuildQuery{config: asq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := asq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := asq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agentstatus.Table, agentstatus.FieldID, selector),
			sqlgraph.To(build.Table, build.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, agentstatus.AgentStatusToBuildTable, agentstatus.AgentStatusToBuildColumn),
		)
		fromU = sqlgraph.SetNeighbors(asq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first AgentStatus entity from the query.
// Returns a *NotFoundError when no AgentStatus was found.
func (asq *AgentStatusQuery) First(ctx context.Context) (*AgentStatus, error) {
	nodes, err := asq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{agentstatus.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (asq *AgentStatusQuery) FirstX(ctx context.Context) *AgentStatus {
	node, err := asq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AgentStatus ID from the query.
// Returns a *NotFoundError when no AgentStatus ID was found.
func (asq *AgentStatusQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = asq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{agentstatus.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (asq *AgentStatusQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := asq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AgentStatus entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AgentStatus entity is found.
// Returns a *NotFoundError when no AgentStatus entities are found.
func (asq *AgentStatusQuery) Only(ctx context.Context) (*AgentStatus, error) {
	nodes, err := asq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{agentstatus.Label}
	default:
		return nil, &NotSingularError{agentstatus.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (asq *AgentStatusQuery) OnlyX(ctx context.Context) *AgentStatus {
	node, err := asq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AgentStatus ID in the query.
// Returns a *NotSingularError when more than one AgentStatus ID is found.
// Returns a *NotFoundError when no entities are found.
func (asq *AgentStatusQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = asq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{agentstatus.Label}
	default:
		err = &NotSingularError{agentstatus.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (asq *AgentStatusQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := asq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AgentStatusSlice.
func (asq *AgentStatusQuery) All(ctx context.Context) ([]*AgentStatus, error) {
	if err := asq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return asq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (asq *AgentStatusQuery) AllX(ctx context.Context) []*AgentStatus {
	nodes, err := asq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AgentStatus IDs.
func (asq *AgentStatusQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := asq.Select(agentstatus.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (asq *AgentStatusQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := asq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (asq *AgentStatusQuery) Count(ctx context.Context) (int, error) {
	if err := asq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return asq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (asq *AgentStatusQuery) CountX(ctx context.Context) int {
	count, err := asq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (asq *AgentStatusQuery) Exist(ctx context.Context) (bool, error) {
	if err := asq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return asq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (asq *AgentStatusQuery) ExistX(ctx context.Context) bool {
	exist, err := asq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AgentStatusQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (asq *AgentStatusQuery) Clone() *AgentStatusQuery {
	if asq == nil {
		return nil
	}
	return &AgentStatusQuery{
		config:                              asq.config,
		limit:                               asq.limit,
		offset:                              asq.offset,
		order:                               append([]OrderFunc{}, asq.order...),
		predicates:                          append([]predicate.AgentStatus{}, asq.predicates...),
		withAgentStatusToProvisionedHost:    asq.withAgentStatusToProvisionedHost.Clone(),
		withAgentStatusToProvisionedNetwork: asq.withAgentStatusToProvisionedNetwork.Clone(),
		withAgentStatusToBuild:              asq.withAgentStatusToBuild.Clone(),
		// clone intermediate query.
		sql:    asq.sql.Clone(),
		path:   asq.path,
		unique: asq.unique,
	}
}

// WithAgentStatusToProvisionedHost tells the query-builder to eager-load the nodes that are connected to
// the "AgentStatusToProvisionedHost" edge. The optional arguments are used to configure the query builder of the edge.
func (asq *AgentStatusQuery) WithAgentStatusToProvisionedHost(opts ...func(*ProvisionedHostQuery)) *AgentStatusQuery {
	query := &ProvisionedHostQuery{config: asq.config}
	for _, opt := range opts {
		opt(query)
	}
	asq.withAgentStatusToProvisionedHost = query
	return asq
}

// WithAgentStatusToProvisionedNetwork tells the query-builder to eager-load the nodes that are connected to
// the "AgentStatusToProvisionedNetwork" edge. The optional arguments are used to configure the query builder of the edge.
func (asq *AgentStatusQuery) WithAgentStatusToProvisionedNetwork(opts ...func(*ProvisionedNetworkQuery)) *AgentStatusQuery {
	query := &ProvisionedNetworkQuery{config: asq.config}
	for _, opt := range opts {
		opt(query)
	}
	asq.withAgentStatusToProvisionedNetwork = query
	return asq
}

// WithAgentStatusToBuild tells the query-builder to eager-load the nodes that are connected to
// the "AgentStatusToBuild" edge. The optional arguments are used to configure the query builder of the edge.
func (asq *AgentStatusQuery) WithAgentStatusToBuild(opts ...func(*BuildQuery)) *AgentStatusQuery {
	query := &BuildQuery{config: asq.config}
	for _, opt := range opts {
		opt(query)
	}
	asq.withAgentStatusToBuild = query
	return asq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		ClientID string `json:"ClientID,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.AgentStatus.Query().
//		GroupBy(agentstatus.FieldClientID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
//
func (asq *AgentStatusQuery) GroupBy(field string, fields ...string) *AgentStatusGroupBy {
	grbuild := &AgentStatusGroupBy{config: asq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := asq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return asq.sqlQuery(ctx), nil
	}
	grbuild.label = agentstatus.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		ClientID string `json:"ClientID,omitempty"`
//	}
//
//	client.AgentStatus.Query().
//		Select(agentstatus.FieldClientID).
//		Scan(ctx, &v)
//
func (asq *AgentStatusQuery) Select(fields ...string) *AgentStatusSelect {
	asq.fields = append(asq.fields, fields...)
	selbuild := &AgentStatusSelect{AgentStatusQuery: asq}
	selbuild.label = agentstatus.Label
	selbuild.flds, selbuild.scan = &asq.fields, selbuild.Scan
	return selbuild
}

func (asq *AgentStatusQuery) prepareQuery(ctx context.Context) error {
	for _, f := range asq.fields {
		if !agentstatus.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if asq.path != nil {
		prev, err := asq.path(ctx)
		if err != nil {
			return err
		}
		asq.sql = prev
	}
	return nil
}

func (asq *AgentStatusQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AgentStatus, error) {
	var (
		nodes       = []*AgentStatus{}
		withFKs     = asq.withFKs
		_spec       = asq.querySpec()
		loadedTypes = [3]bool{
			asq.withAgentStatusToProvisionedHost != nil,
			asq.withAgentStatusToProvisionedNetwork != nil,
			asq.withAgentStatusToBuild != nil,
		}
	)
	if asq.withAgentStatusToProvisionedHost != nil || asq.withAgentStatusToProvisionedNetwork != nil || asq.withAgentStatusToBuild != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, agentstatus.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*AgentStatus).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &AgentStatus{config: asq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, asq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := asq.withAgentStatusToProvisionedHost; query != nil {
		if err := asq.loadAgentStatusToProvisionedHost(ctx, query, nodes, nil,
			func(n *AgentStatus, e *ProvisionedHost) { n.Edges.AgentStatusToProvisionedHost = e }); err != nil {
			return nil, err
		}
	}
	if query := asq.withAgentStatusToProvisionedNetwork; query != nil {
		if err := asq.loadAgentStatusToProvisionedNetwork(ctx, query, nodes, nil,
			func(n *AgentStatus, e *ProvisionedNetwork) { n.Edges.AgentStatusToProvisionedNetwork = e }); err != nil {
			return nil, err
		}
	}
	if query := asq.withAgentStatusToBuild; query != nil {
		if err := asq.loadAgentStatusToBuild(ctx, query, nodes, nil,
			func(n *AgentStatus, e *Build) { n.Edges.AgentStatusToBuild = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (asq *AgentStatusQuery) loadAgentStatusToProvisionedHost(ctx context.Context, query *ProvisionedHostQuery, nodes []*AgentStatus, init func(*AgentStatus), assign func(*AgentStatus, *ProvisionedHost)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*AgentStatus)
	for i := range nodes {
		if nodes[i].agent_status_agent_status_to_provisioned_host == nil {
			continue
		}
		fk := *nodes[i].agent_status_agent_status_to_provisioned_host
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(provisionedhost.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "agent_status_agent_status_to_provisioned_host" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (asq *AgentStatusQuery) loadAgentStatusToProvisionedNetwork(ctx context.Context, query *ProvisionedNetworkQuery, nodes []*AgentStatus, init func(*AgentStatus), assign func(*AgentStatus, *ProvisionedNetwork)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*AgentStatus)
	for i := range nodes {
		if nodes[i].agent_status_agent_status_to_provisioned_network == nil {
			continue
		}
		fk := *nodes[i].agent_status_agent_status_to_provisioned_network
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(provisionednetwork.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "agent_status_agent_status_to_provisioned_network" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (asq *AgentStatusQuery) loadAgentStatusToBuild(ctx context.Context, query *BuildQuery, nodes []*AgentStatus, init func(*AgentStatus), assign func(*AgentStatus, *Build)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*AgentStatus)
	for i := range nodes {
		if nodes[i].agent_status_agent_status_to_build == nil {
			continue
		}
		fk := *nodes[i].agent_status_agent_status_to_build
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(build.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "agent_status_agent_status_to_build" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (asq *AgentStatusQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := asq.querySpec()
	_spec.Node.Columns = asq.fields
	if len(asq.fields) > 0 {
		_spec.Unique = asq.unique != nil && *asq.unique
	}
	return sqlgraph.CountNodes(ctx, asq.driver, _spec)
}

func (asq *AgentStatusQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := asq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (asq *AgentStatusQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   agentstatus.Table,
			Columns: agentstatus.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: agentstatus.FieldID,
			},
		},
		From:   asq.sql,
		Unique: true,
	}
	if unique := asq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := asq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, agentstatus.FieldID)
		for i := range fields {
			if fields[i] != agentstatus.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := asq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := asq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := asq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := asq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (asq *AgentStatusQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(asq.driver.Dialect())
	t1 := builder.Table(agentstatus.Table)
	columns := asq.fields
	if len(columns) == 0 {
		columns = agentstatus.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if asq.sql != nil {
		selector = asq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if asq.unique != nil && *asq.unique {
		selector.Distinct()
	}
	for _, p := range asq.predicates {
		p(selector)
	}
	for _, p := range asq.order {
		p(selector)
	}
	if offset := asq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := asq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AgentStatusGroupBy is the group-by builder for AgentStatus entities.
type AgentStatusGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (asgb *AgentStatusGroupBy) Aggregate(fns ...AggregateFunc) *AgentStatusGroupBy {
	asgb.fns = append(asgb.fns, fns...)
	return asgb
}

// Scan applies the group-by query and scans the result into the given value.
func (asgb *AgentStatusGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := asgb.path(ctx)
	if err != nil {
		return err
	}
	asgb.sql = query
	return asgb.sqlScan(ctx, v)
}

func (asgb *AgentStatusGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range asgb.fields {
		if !agentstatus.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := asgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := asgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (asgb *AgentStatusGroupBy) sqlQuery() *sql.Selector {
	selector := asgb.sql.Select()
	aggregation := make([]string, 0, len(asgb.fns))
	for _, fn := range asgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(asgb.fields)+len(asgb.fns))
		for _, f := range asgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(asgb.fields...)...)
}

// AgentStatusSelect is the builder for selecting fields of AgentStatus entities.
type AgentStatusSelect struct {
	*AgentStatusQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (ass *AgentStatusSelect) Scan(ctx context.Context, v interface{}) error {
	if err := ass.prepareQuery(ctx); err != nil {
		return err
	}
	ass.sql = ass.AgentStatusQuery.sqlQuery(ctx)
	return ass.sqlScan(ctx, v)
}

func (ass *AgentStatusSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := ass.sql.Query()
	if err := ass.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
