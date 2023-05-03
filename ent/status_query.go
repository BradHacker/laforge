// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/gen0cide/laforge/ent/adhocplan"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/provisioningscheduledstep"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/gen0cide/laforge/ent/servertask"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/gen0cide/laforge/ent/team"
	"github.com/google/uuid"
)

// StatusQuery is the builder for querying Status entities.
type StatusQuery struct {
	config
	limit                         *int
	offset                        *int
	unique                        *bool
	order                         []OrderFunc
	fields                        []string
	predicates                    []predicate.Status
	withBuild                     *BuildQuery
	withProvisionedNetwork        *ProvisionedNetworkQuery
	withProvisionedHost           *ProvisionedHostQuery
	withProvisioningStep          *ProvisioningStepQuery
	withTeam                      *TeamQuery
	withPlan                      *PlanQuery
	withServerTask                *ServerTaskQuery
	withAdhocPlan                 *AdhocPlanQuery
	withProvisioningScheduledStep *ProvisioningScheduledStepQuery
	withFKs                       bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the StatusQuery builder.
func (sq *StatusQuery) Where(ps ...predicate.Status) *StatusQuery {
	sq.predicates = append(sq.predicates, ps...)
	return sq
}

// Limit adds a limit step to the query.
func (sq *StatusQuery) Limit(limit int) *StatusQuery {
	sq.limit = &limit
	return sq
}

// Offset adds an offset step to the query.
func (sq *StatusQuery) Offset(offset int) *StatusQuery {
	sq.offset = &offset
	return sq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (sq *StatusQuery) Unique(unique bool) *StatusQuery {
	sq.unique = &unique
	return sq
}

// Order adds an order step to the query.
func (sq *StatusQuery) Order(o ...OrderFunc) *StatusQuery {
	sq.order = append(sq.order, o...)
	return sq
}

// QueryBuild chains the current query on the "Build" edge.
func (sq *StatusQuery) QueryBuild() *BuildQuery {
	query := &BuildQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(build.Table, build.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.BuildTable, status.BuildColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisionedNetwork chains the current query on the "ProvisionedNetwork" edge.
func (sq *StatusQuery) QueryProvisionedNetwork() *ProvisionedNetworkQuery {
	query := &ProvisionedNetworkQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(provisionednetwork.Table, provisionednetwork.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.ProvisionedNetworkTable, status.ProvisionedNetworkColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisionedHost chains the current query on the "ProvisionedHost" edge.
func (sq *StatusQuery) QueryProvisionedHost() *ProvisionedHostQuery {
	query := &ProvisionedHostQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(provisionedhost.Table, provisionedhost.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.ProvisionedHostTable, status.ProvisionedHostColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisioningStep chains the current query on the "ProvisioningStep" edge.
func (sq *StatusQuery) QueryProvisioningStep() *ProvisioningStepQuery {
	query := &ProvisioningStepQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(provisioningstep.Table, provisioningstep.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.ProvisioningStepTable, status.ProvisioningStepColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryTeam chains the current query on the "Team" edge.
func (sq *StatusQuery) QueryTeam() *TeamQuery {
	query := &TeamQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(team.Table, team.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.TeamTable, status.TeamColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryPlan chains the current query on the "Plan" edge.
func (sq *StatusQuery) QueryPlan() *PlanQuery {
	query := &PlanQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(plan.Table, plan.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.PlanTable, status.PlanColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryServerTask chains the current query on the "ServerTask" edge.
func (sq *StatusQuery) QueryServerTask() *ServerTaskQuery {
	query := &ServerTaskQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(servertask.Table, servertask.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.ServerTaskTable, status.ServerTaskColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAdhocPlan chains the current query on the "AdhocPlan" edge.
func (sq *StatusQuery) QueryAdhocPlan() *AdhocPlanQuery {
	query := &AdhocPlanQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(adhocplan.Table, adhocplan.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.AdhocPlanTable, status.AdhocPlanColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisioningScheduledStep chains the current query on the "ProvisioningScheduledStep" edge.
func (sq *StatusQuery) QueryProvisioningScheduledStep() *ProvisioningScheduledStepQuery {
	query := &ProvisioningScheduledStepQuery{config: sq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := sq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(status.Table, status.FieldID, selector),
			sqlgraph.To(provisioningscheduledstep.Table, provisioningscheduledstep.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, status.ProvisioningScheduledStepTable, status.ProvisioningScheduledStepColumn),
		)
		fromU = sqlgraph.SetNeighbors(sq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Status entity from the query.
// Returns a *NotFoundError when no Status was found.
func (sq *StatusQuery) First(ctx context.Context) (*Status, error) {
	nodes, err := sq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{status.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (sq *StatusQuery) FirstX(ctx context.Context) *Status {
	node, err := sq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Status ID from the query.
// Returns a *NotFoundError when no Status ID was found.
func (sq *StatusQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = sq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{status.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (sq *StatusQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := sq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Status entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Status entity is found.
// Returns a *NotFoundError when no Status entities are found.
func (sq *StatusQuery) Only(ctx context.Context) (*Status, error) {
	nodes, err := sq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{status.Label}
	default:
		return nil, &NotSingularError{status.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (sq *StatusQuery) OnlyX(ctx context.Context) *Status {
	node, err := sq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Status ID in the query.
// Returns a *NotSingularError when more than one Status ID is found.
// Returns a *NotFoundError when no entities are found.
func (sq *StatusQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = sq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{status.Label}
	default:
		err = &NotSingularError{status.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (sq *StatusQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := sq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of StatusSlice.
func (sq *StatusQuery) All(ctx context.Context) ([]*Status, error) {
	if err := sq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return sq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (sq *StatusQuery) AllX(ctx context.Context) []*Status {
	nodes, err := sq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Status IDs.
func (sq *StatusQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := sq.Select(status.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (sq *StatusQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := sq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (sq *StatusQuery) Count(ctx context.Context) (int, error) {
	if err := sq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return sq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (sq *StatusQuery) CountX(ctx context.Context) int {
	count, err := sq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (sq *StatusQuery) Exist(ctx context.Context) (bool, error) {
	if err := sq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return sq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (sq *StatusQuery) ExistX(ctx context.Context) bool {
	exist, err := sq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the StatusQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (sq *StatusQuery) Clone() *StatusQuery {
	if sq == nil {
		return nil
	}
	return &StatusQuery{
		config:                        sq.config,
		limit:                         sq.limit,
		offset:                        sq.offset,
		order:                         append([]OrderFunc{}, sq.order...),
		predicates:                    append([]predicate.Status{}, sq.predicates...),
		withBuild:                     sq.withBuild.Clone(),
		withProvisionedNetwork:        sq.withProvisionedNetwork.Clone(),
		withProvisionedHost:           sq.withProvisionedHost.Clone(),
		withProvisioningStep:          sq.withProvisioningStep.Clone(),
		withTeam:                      sq.withTeam.Clone(),
		withPlan:                      sq.withPlan.Clone(),
		withServerTask:                sq.withServerTask.Clone(),
		withAdhocPlan:                 sq.withAdhocPlan.Clone(),
		withProvisioningScheduledStep: sq.withProvisioningScheduledStep.Clone(),
		// clone intermediate query.
		sql:    sq.sql.Clone(),
		path:   sq.path,
		unique: sq.unique,
	}
}

// WithBuild tells the query-builder to eager-load the nodes that are connected to
// the "Build" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithBuild(opts ...func(*BuildQuery)) *StatusQuery {
	query := &BuildQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withBuild = query
	return sq
}

// WithProvisionedNetwork tells the query-builder to eager-load the nodes that are connected to
// the "ProvisionedNetwork" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithProvisionedNetwork(opts ...func(*ProvisionedNetworkQuery)) *StatusQuery {
	query := &ProvisionedNetworkQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withProvisionedNetwork = query
	return sq
}

// WithProvisionedHost tells the query-builder to eager-load the nodes that are connected to
// the "ProvisionedHost" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithProvisionedHost(opts ...func(*ProvisionedHostQuery)) *StatusQuery {
	query := &ProvisionedHostQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withProvisionedHost = query
	return sq
}

// WithProvisioningStep tells the query-builder to eager-load the nodes that are connected to
// the "ProvisioningStep" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithProvisioningStep(opts ...func(*ProvisioningStepQuery)) *StatusQuery {
	query := &ProvisioningStepQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withProvisioningStep = query
	return sq
}

// WithTeam tells the query-builder to eager-load the nodes that are connected to
// the "Team" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithTeam(opts ...func(*TeamQuery)) *StatusQuery {
	query := &TeamQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withTeam = query
	return sq
}

// WithPlan tells the query-builder to eager-load the nodes that are connected to
// the "Plan" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithPlan(opts ...func(*PlanQuery)) *StatusQuery {
	query := &PlanQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withPlan = query
	return sq
}

// WithServerTask tells the query-builder to eager-load the nodes that are connected to
// the "ServerTask" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithServerTask(opts ...func(*ServerTaskQuery)) *StatusQuery {
	query := &ServerTaskQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withServerTask = query
	return sq
}

// WithAdhocPlan tells the query-builder to eager-load the nodes that are connected to
// the "AdhocPlan" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithAdhocPlan(opts ...func(*AdhocPlanQuery)) *StatusQuery {
	query := &AdhocPlanQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withAdhocPlan = query
	return sq
}

// WithProvisioningScheduledStep tells the query-builder to eager-load the nodes that are connected to
// the "ProvisioningScheduledStep" edge. The optional arguments are used to configure the query builder of the edge.
func (sq *StatusQuery) WithProvisioningScheduledStep(opts ...func(*ProvisioningScheduledStepQuery)) *StatusQuery {
	query := &ProvisioningScheduledStepQuery{config: sq.config}
	for _, opt := range opts {
		opt(query)
	}
	sq.withProvisioningScheduledStep = query
	return sq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		State status.State `json:"state,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Status.Query().
//		GroupBy(status.FieldState).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (sq *StatusQuery) GroupBy(field string, fields ...string) *StatusGroupBy {
	grbuild := &StatusGroupBy{config: sq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := sq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return sq.sqlQuery(ctx), nil
	}
	grbuild.label = status.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		State status.State `json:"state,omitempty"`
//	}
//
//	client.Status.Query().
//		Select(status.FieldState).
//		Scan(ctx, &v)
func (sq *StatusQuery) Select(fields ...string) *StatusSelect {
	sq.fields = append(sq.fields, fields...)
	selbuild := &StatusSelect{StatusQuery: sq}
	selbuild.label = status.Label
	selbuild.flds, selbuild.scan = &sq.fields, selbuild.Scan
	return selbuild
}

func (sq *StatusQuery) prepareQuery(ctx context.Context) error {
	for _, f := range sq.fields {
		if !status.ValidColumn(f) {
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

func (sq *StatusQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Status, error) {
	var (
		nodes       = []*Status{}
		withFKs     = sq.withFKs
		_spec       = sq.querySpec()
		loadedTypes = [9]bool{
			sq.withBuild != nil,
			sq.withProvisionedNetwork != nil,
			sq.withProvisionedHost != nil,
			sq.withProvisioningStep != nil,
			sq.withTeam != nil,
			sq.withPlan != nil,
			sq.withServerTask != nil,
			sq.withAdhocPlan != nil,
			sq.withProvisioningScheduledStep != nil,
		}
	)
	if sq.withBuild != nil || sq.withProvisionedNetwork != nil || sq.withProvisionedHost != nil || sq.withProvisioningStep != nil || sq.withTeam != nil || sq.withPlan != nil || sq.withServerTask != nil || sq.withAdhocPlan != nil || sq.withProvisioningScheduledStep != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, status.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*Status).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &Status{config: sq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
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
	if query := sq.withBuild; query != nil {
		if err := sq.loadBuild(ctx, query, nodes, nil,
			func(n *Status, e *Build) { n.Edges.Build = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withProvisionedNetwork; query != nil {
		if err := sq.loadProvisionedNetwork(ctx, query, nodes, nil,
			func(n *Status, e *ProvisionedNetwork) { n.Edges.ProvisionedNetwork = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withProvisionedHost; query != nil {
		if err := sq.loadProvisionedHost(ctx, query, nodes, nil,
			func(n *Status, e *ProvisionedHost) { n.Edges.ProvisionedHost = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withProvisioningStep; query != nil {
		if err := sq.loadProvisioningStep(ctx, query, nodes, nil,
			func(n *Status, e *ProvisioningStep) { n.Edges.ProvisioningStep = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withTeam; query != nil {
		if err := sq.loadTeam(ctx, query, nodes, nil,
			func(n *Status, e *Team) { n.Edges.Team = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withPlan; query != nil {
		if err := sq.loadPlan(ctx, query, nodes, nil,
			func(n *Status, e *Plan) { n.Edges.Plan = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withServerTask; query != nil {
		if err := sq.loadServerTask(ctx, query, nodes, nil,
			func(n *Status, e *ServerTask) { n.Edges.ServerTask = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withAdhocPlan; query != nil {
		if err := sq.loadAdhocPlan(ctx, query, nodes, nil,
			func(n *Status, e *AdhocPlan) { n.Edges.AdhocPlan = e }); err != nil {
			return nil, err
		}
	}
	if query := sq.withProvisioningScheduledStep; query != nil {
		if err := sq.loadProvisioningScheduledStep(ctx, query, nodes, nil,
			func(n *Status, e *ProvisioningScheduledStep) { n.Edges.ProvisioningScheduledStep = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (sq *StatusQuery) loadBuild(ctx context.Context, query *BuildQuery, nodes []*Status, init func(*Status), assign func(*Status, *Build)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].build_status == nil {
			continue
		}
		fk := *nodes[i].build_status
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
			return fmt.Errorf(`unexpected foreign-key "build_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadProvisionedNetwork(ctx context.Context, query *ProvisionedNetworkQuery, nodes []*Status, init func(*Status), assign func(*Status, *ProvisionedNetwork)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].provisioned_network_status == nil {
			continue
		}
		fk := *nodes[i].provisioned_network_status
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
			return fmt.Errorf(`unexpected foreign-key "provisioned_network_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadProvisionedHost(ctx context.Context, query *ProvisionedHostQuery, nodes []*Status, init func(*Status), assign func(*Status, *ProvisionedHost)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].provisioned_host_status == nil {
			continue
		}
		fk := *nodes[i].provisioned_host_status
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
			return fmt.Errorf(`unexpected foreign-key "provisioned_host_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadProvisioningStep(ctx context.Context, query *ProvisioningStepQuery, nodes []*Status, init func(*Status), assign func(*Status, *ProvisioningStep)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].provisioning_step_status == nil {
			continue
		}
		fk := *nodes[i].provisioning_step_status
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(provisioningstep.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "provisioning_step_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadTeam(ctx context.Context, query *TeamQuery, nodes []*Status, init func(*Status), assign func(*Status, *Team)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].team_status == nil {
			continue
		}
		fk := *nodes[i].team_status
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(team.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "team_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadPlan(ctx context.Context, query *PlanQuery, nodes []*Status, init func(*Status), assign func(*Status, *Plan)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].plan_status == nil {
			continue
		}
		fk := *nodes[i].plan_status
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(plan.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "plan_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadServerTask(ctx context.Context, query *ServerTaskQuery, nodes []*Status, init func(*Status), assign func(*Status, *ServerTask)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].server_task_status == nil {
			continue
		}
		fk := *nodes[i].server_task_status
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(servertask.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "server_task_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadAdhocPlan(ctx context.Context, query *AdhocPlanQuery, nodes []*Status, init func(*Status), assign func(*Status, *AdhocPlan)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].adhoc_plan_status == nil {
			continue
		}
		fk := *nodes[i].adhoc_plan_status
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(adhocplan.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "adhoc_plan_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (sq *StatusQuery) loadProvisioningScheduledStep(ctx context.Context, query *ProvisioningScheduledStepQuery, nodes []*Status, init func(*Status), assign func(*Status, *ProvisioningScheduledStep)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Status)
	for i := range nodes {
		if nodes[i].provisioning_scheduled_step_status == nil {
			continue
		}
		fk := *nodes[i].provisioning_scheduled_step_status
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	query.Where(provisioningscheduledstep.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "provisioning_scheduled_step_status" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (sq *StatusQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := sq.querySpec()
	_spec.Node.Columns = sq.fields
	if len(sq.fields) > 0 {
		_spec.Unique = sq.unique != nil && *sq.unique
	}
	return sqlgraph.CountNodes(ctx, sq.driver, _spec)
}

func (sq *StatusQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := sq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (sq *StatusQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   status.Table,
			Columns: status.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: status.FieldID,
			},
		},
		From:   sq.sql,
		Unique: true,
	}
	if unique := sq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := sq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, status.FieldID)
		for i := range fields {
			if fields[i] != status.FieldID {
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
	if limit := sq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := sq.offset; offset != nil {
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

func (sq *StatusQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(sq.driver.Dialect())
	t1 := builder.Table(status.Table)
	columns := sq.fields
	if len(columns) == 0 {
		columns = status.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if sq.sql != nil {
		selector = sq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if sq.unique != nil && *sq.unique {
		selector.Distinct()
	}
	for _, p := range sq.predicates {
		p(selector)
	}
	for _, p := range sq.order {
		p(selector)
	}
	if offset := sq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := sq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// StatusGroupBy is the group-by builder for Status entities.
type StatusGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (sgb *StatusGroupBy) Aggregate(fns ...AggregateFunc) *StatusGroupBy {
	sgb.fns = append(sgb.fns, fns...)
	return sgb
}

// Scan applies the group-by query and scans the result into the given value.
func (sgb *StatusGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := sgb.path(ctx)
	if err != nil {
		return err
	}
	sgb.sql = query
	return sgb.sqlScan(ctx, v)
}

func (sgb *StatusGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range sgb.fields {
		if !status.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := sgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := sgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (sgb *StatusGroupBy) sqlQuery() *sql.Selector {
	selector := sgb.sql.Select()
	aggregation := make([]string, 0, len(sgb.fns))
	for _, fn := range sgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(sgb.fields)+len(sgb.fns))
		for _, f := range sgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(sgb.fields...)...)
}

// StatusSelect is the builder for selecting fields of Status entities.
type StatusSelect struct {
	*StatusQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (ss *StatusSelect) Scan(ctx context.Context, v interface{}) error {
	if err := ss.prepareQuery(ctx); err != nil {
		return err
	}
	ss.sql = ss.StatusQuery.sqlQuery(ctx)
	return ss.sqlScan(ctx, v)
}

func (ss *StatusSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := ss.sql.Query()
	if err := ss.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
