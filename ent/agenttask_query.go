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
	"github.com/gen0cide/laforge/ent/adhocplan"
	"github.com/gen0cide/laforge/ent/agenttask"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionedschedulestep"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/google/uuid"
)

// AgentTaskQuery is the builder for querying AgentTask entities.
type AgentTaskQuery struct {
	config
	limit                                  *int
	offset                                 *int
	unique                                 *bool
	order                                  []OrderFunc
	fields                                 []string
	predicates                             []predicate.AgentTask
	withAgentTaskToProvisioningStep        *ProvisioningStepQuery
	withAgentTaskToProvisionedHost         *ProvisionedHostQuery
	withAgentTaskToProvisionedScheduleStep *ProvisionedScheduleStepQuery
	withAgentTaskToAdhocPlan               *AdhocPlanQuery
	withFKs                                bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AgentTaskQuery builder.
func (atq *AgentTaskQuery) Where(ps ...predicate.AgentTask) *AgentTaskQuery {
	atq.predicates = append(atq.predicates, ps...)
	return atq
}

// Limit adds a limit step to the query.
func (atq *AgentTaskQuery) Limit(limit int) *AgentTaskQuery {
	atq.limit = &limit
	return atq
}

// Offset adds an offset step to the query.
func (atq *AgentTaskQuery) Offset(offset int) *AgentTaskQuery {
	atq.offset = &offset
	return atq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (atq *AgentTaskQuery) Unique(unique bool) *AgentTaskQuery {
	atq.unique = &unique
	return atq
}

// Order adds an order step to the query.
func (atq *AgentTaskQuery) Order(o ...OrderFunc) *AgentTaskQuery {
	atq.order = append(atq.order, o...)
	return atq
}

// QueryAgentTaskToProvisioningStep chains the current query on the "AgentTaskToProvisioningStep" edge.
func (atq *AgentTaskQuery) QueryAgentTaskToProvisioningStep() *ProvisioningStepQuery {
	query := &ProvisioningStepQuery{config: atq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := atq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := atq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agenttask.Table, agenttask.FieldID, selector),
			sqlgraph.To(provisioningstep.Table, provisioningstep.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, agenttask.AgentTaskToProvisioningStepTable, agenttask.AgentTaskToProvisioningStepColumn),
		)
		fromU = sqlgraph.SetNeighbors(atq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAgentTaskToProvisionedHost chains the current query on the "AgentTaskToProvisionedHost" edge.
func (atq *AgentTaskQuery) QueryAgentTaskToProvisionedHost() *ProvisionedHostQuery {
	query := &ProvisionedHostQuery{config: atq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := atq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := atq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agenttask.Table, agenttask.FieldID, selector),
			sqlgraph.To(provisionedhost.Table, provisionedhost.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, agenttask.AgentTaskToProvisionedHostTable, agenttask.AgentTaskToProvisionedHostColumn),
		)
		fromU = sqlgraph.SetNeighbors(atq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAgentTaskToProvisionedScheduleStep chains the current query on the "AgentTaskToProvisionedScheduleStep" edge.
func (atq *AgentTaskQuery) QueryAgentTaskToProvisionedScheduleStep() *ProvisionedScheduleStepQuery {
	query := &ProvisionedScheduleStepQuery{config: atq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := atq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := atq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agenttask.Table, agenttask.FieldID, selector),
			sqlgraph.To(provisionedschedulestep.Table, provisionedschedulestep.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, agenttask.AgentTaskToProvisionedScheduleStepTable, agenttask.AgentTaskToProvisionedScheduleStepColumn),
		)
		fromU = sqlgraph.SetNeighbors(atq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAgentTaskToAdhocPlan chains the current query on the "AgentTaskToAdhocPlan" edge.
func (atq *AgentTaskQuery) QueryAgentTaskToAdhocPlan() *AdhocPlanQuery {
	query := &AdhocPlanQuery{config: atq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := atq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := atq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(agenttask.Table, agenttask.FieldID, selector),
			sqlgraph.To(adhocplan.Table, adhocplan.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, agenttask.AgentTaskToAdhocPlanTable, agenttask.AgentTaskToAdhocPlanColumn),
		)
		fromU = sqlgraph.SetNeighbors(atq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first AgentTask entity from the query.
// Returns a *NotFoundError when no AgentTask was found.
func (atq *AgentTaskQuery) First(ctx context.Context) (*AgentTask, error) {
	nodes, err := atq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{agenttask.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (atq *AgentTaskQuery) FirstX(ctx context.Context) *AgentTask {
	node, err := atq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AgentTask ID from the query.
// Returns a *NotFoundError when no AgentTask ID was found.
func (atq *AgentTaskQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = atq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{agenttask.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (atq *AgentTaskQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := atq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AgentTask entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AgentTask entity is found.
// Returns a *NotFoundError when no AgentTask entities are found.
func (atq *AgentTaskQuery) Only(ctx context.Context) (*AgentTask, error) {
	nodes, err := atq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{agenttask.Label}
	default:
		return nil, &NotSingularError{agenttask.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (atq *AgentTaskQuery) OnlyX(ctx context.Context) *AgentTask {
	node, err := atq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AgentTask ID in the query.
// Returns a *NotSingularError when more than one AgentTask ID is found.
// Returns a *NotFoundError when no entities are found.
func (atq *AgentTaskQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = atq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{agenttask.Label}
	default:
		err = &NotSingularError{agenttask.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (atq *AgentTaskQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := atq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AgentTasks.
func (atq *AgentTaskQuery) All(ctx context.Context) ([]*AgentTask, error) {
	if err := atq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return atq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (atq *AgentTaskQuery) AllX(ctx context.Context) []*AgentTask {
	nodes, err := atq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AgentTask IDs.
func (atq *AgentTaskQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := atq.Select(agenttask.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (atq *AgentTaskQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := atq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (atq *AgentTaskQuery) Count(ctx context.Context) (int, error) {
	if err := atq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return atq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (atq *AgentTaskQuery) CountX(ctx context.Context) int {
	count, err := atq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (atq *AgentTaskQuery) Exist(ctx context.Context) (bool, error) {
	if err := atq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return atq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (atq *AgentTaskQuery) ExistX(ctx context.Context) bool {
	exist, err := atq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AgentTaskQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (atq *AgentTaskQuery) Clone() *AgentTaskQuery {
	if atq == nil {
		return nil
	}
	return &AgentTaskQuery{
		config:                                 atq.config,
		limit:                                  atq.limit,
		offset:                                 atq.offset,
		order:                                  append([]OrderFunc{}, atq.order...),
		predicates:                             append([]predicate.AgentTask{}, atq.predicates...),
		withAgentTaskToProvisioningStep:        atq.withAgentTaskToProvisioningStep.Clone(),
		withAgentTaskToProvisionedHost:         atq.withAgentTaskToProvisionedHost.Clone(),
		withAgentTaskToProvisionedScheduleStep: atq.withAgentTaskToProvisionedScheduleStep.Clone(),
		withAgentTaskToAdhocPlan:               atq.withAgentTaskToAdhocPlan.Clone(),
		// clone intermediate query.
		sql:    atq.sql.Clone(),
		path:   atq.path,
		unique: atq.unique,
	}
}

// WithAgentTaskToProvisioningStep tells the query-builder to eager-load the nodes that are connected to
// the "AgentTaskToProvisioningStep" edge. The optional arguments are used to configure the query builder of the edge.
func (atq *AgentTaskQuery) WithAgentTaskToProvisioningStep(opts ...func(*ProvisioningStepQuery)) *AgentTaskQuery {
	query := &ProvisioningStepQuery{config: atq.config}
	for _, opt := range opts {
		opt(query)
	}
	atq.withAgentTaskToProvisioningStep = query
	return atq
}

// WithAgentTaskToProvisionedHost tells the query-builder to eager-load the nodes that are connected to
// the "AgentTaskToProvisionedHost" edge. The optional arguments are used to configure the query builder of the edge.
func (atq *AgentTaskQuery) WithAgentTaskToProvisionedHost(opts ...func(*ProvisionedHostQuery)) *AgentTaskQuery {
	query := &ProvisionedHostQuery{config: atq.config}
	for _, opt := range opts {
		opt(query)
	}
	atq.withAgentTaskToProvisionedHost = query
	return atq
}

// WithAgentTaskToProvisionedScheduleStep tells the query-builder to eager-load the nodes that are connected to
// the "AgentTaskToProvisionedScheduleStep" edge. The optional arguments are used to configure the query builder of the edge.
func (atq *AgentTaskQuery) WithAgentTaskToProvisionedScheduleStep(opts ...func(*ProvisionedScheduleStepQuery)) *AgentTaskQuery {
	query := &ProvisionedScheduleStepQuery{config: atq.config}
	for _, opt := range opts {
		opt(query)
	}
	atq.withAgentTaskToProvisionedScheduleStep = query
	return atq
}

// WithAgentTaskToAdhocPlan tells the query-builder to eager-load the nodes that are connected to
// the "AgentTaskToAdhocPlan" edge. The optional arguments are used to configure the query builder of the edge.
func (atq *AgentTaskQuery) WithAgentTaskToAdhocPlan(opts ...func(*AdhocPlanQuery)) *AgentTaskQuery {
	query := &AdhocPlanQuery{config: atq.config}
	for _, opt := range opts {
		opt(query)
	}
	atq.withAgentTaskToAdhocPlan = query
	return atq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Command agenttask.Command `json:"command,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.AgentTask.Query().
//		GroupBy(agenttask.FieldCommand).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (atq *AgentTaskQuery) GroupBy(field string, fields ...string) *AgentTaskGroupBy {
	grbuild := &AgentTaskGroupBy{config: atq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := atq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return atq.sqlQuery(ctx), nil
	}
	grbuild.label = agenttask.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Command agenttask.Command `json:"command,omitempty"`
//	}
//
//	client.AgentTask.Query().
//		Select(agenttask.FieldCommand).
//		Scan(ctx, &v)
func (atq *AgentTaskQuery) Select(fields ...string) *AgentTaskSelect {
	atq.fields = append(atq.fields, fields...)
	selbuild := &AgentTaskSelect{AgentTaskQuery: atq}
	selbuild.label = agenttask.Label
	selbuild.flds, selbuild.scan = &atq.fields, selbuild.Scan
	return selbuild
}

func (atq *AgentTaskQuery) prepareQuery(ctx context.Context) error {
	for _, f := range atq.fields {
		if !agenttask.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if atq.path != nil {
		prev, err := atq.path(ctx)
		if err != nil {
			return err
		}
		atq.sql = prev
	}
	return nil
}

func (atq *AgentTaskQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AgentTask, error) {
	var (
		nodes       = []*AgentTask{}
		withFKs     = atq.withFKs
		_spec       = atq.querySpec()
		loadedTypes = [4]bool{
			atq.withAgentTaskToProvisioningStep != nil,
			atq.withAgentTaskToProvisionedHost != nil,
			atq.withAgentTaskToProvisionedScheduleStep != nil,
			atq.withAgentTaskToAdhocPlan != nil,
		}
	)
	if atq.withAgentTaskToProvisioningStep != nil || atq.withAgentTaskToProvisionedHost != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, agenttask.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*AgentTask).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &AgentTask{config: atq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, atq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := atq.withAgentTaskToProvisioningStep; query != nil {
		if err := atq.loadAgentTaskToProvisioningStep(ctx, query, nodes, nil,
			func(n *AgentTask, e *ProvisioningStep) { n.Edges.AgentTaskToProvisioningStep = e }); err != nil {
			return nil, err
		}
	}
	if query := atq.withAgentTaskToProvisionedHost; query != nil {
		if err := atq.loadAgentTaskToProvisionedHost(ctx, query, nodes, nil,
			func(n *AgentTask, e *ProvisionedHost) { n.Edges.AgentTaskToProvisionedHost = e }); err != nil {
			return nil, err
		}
	}
	if query := atq.withAgentTaskToProvisionedScheduleStep; query != nil {
		if err := atq.loadAgentTaskToProvisionedScheduleStep(ctx, query, nodes, nil,
			func(n *AgentTask, e *ProvisionedScheduleStep) { n.Edges.AgentTaskToProvisionedScheduleStep = e }); err != nil {
			return nil, err
		}
	}
	if query := atq.withAgentTaskToAdhocPlan; query != nil {
		if err := atq.loadAgentTaskToAdhocPlan(ctx, query, nodes,
			func(n *AgentTask) { n.Edges.AgentTaskToAdhocPlan = []*AdhocPlan{} },
			func(n *AgentTask, e *AdhocPlan) {
				n.Edges.AgentTaskToAdhocPlan = append(n.Edges.AgentTaskToAdhocPlan, e)
			}); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (atq *AgentTaskQuery) loadAgentTaskToProvisioningStep(ctx context.Context, query *ProvisioningStepQuery, nodes []*AgentTask, init func(*AgentTask), assign func(*AgentTask, *ProvisioningStep)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*AgentTask)
	for i := range nodes {
		if nodes[i].agent_task_agent_task_to_provisioning_step == nil {
			continue
		}
		fk := *nodes[i].agent_task_agent_task_to_provisioning_step
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
			return fmt.Errorf(`unexpected foreign-key "agent_task_agent_task_to_provisioning_step" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (atq *AgentTaskQuery) loadAgentTaskToProvisionedHost(ctx context.Context, query *ProvisionedHostQuery, nodes []*AgentTask, init func(*AgentTask), assign func(*AgentTask, *ProvisionedHost)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*AgentTask)
	for i := range nodes {
		if nodes[i].agent_task_agent_task_to_provisioned_host == nil {
			continue
		}
		fk := *nodes[i].agent_task_agent_task_to_provisioned_host
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
			return fmt.Errorf(`unexpected foreign-key "agent_task_agent_task_to_provisioned_host" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (atq *AgentTaskQuery) loadAgentTaskToProvisionedScheduleStep(ctx context.Context, query *ProvisionedScheduleStepQuery, nodes []*AgentTask, init func(*AgentTask), assign func(*AgentTask, *ProvisionedScheduleStep)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*AgentTask)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.ProvisionedScheduleStep(func(s *sql.Selector) {
		s.Where(sql.InValues(agenttask.AgentTaskToProvisionedScheduleStepColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.agent_task_agent_task_to_provisioned_schedule_step
		if fk == nil {
			return fmt.Errorf(`foreign-key "agent_task_agent_task_to_provisioned_schedule_step" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "agent_task_agent_task_to_provisioned_schedule_step" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (atq *AgentTaskQuery) loadAgentTaskToAdhocPlan(ctx context.Context, query *AdhocPlanQuery, nodes []*AgentTask, init func(*AgentTask), assign func(*AgentTask, *AdhocPlan)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*AgentTask)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.AdhocPlan(func(s *sql.Selector) {
		s.Where(sql.InValues(agenttask.AgentTaskToAdhocPlanColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.adhoc_plan_adhoc_plan_to_agent_task
		if fk == nil {
			return fmt.Errorf(`foreign-key "adhoc_plan_adhoc_plan_to_agent_task" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "adhoc_plan_adhoc_plan_to_agent_task" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (atq *AgentTaskQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := atq.querySpec()
	_spec.Node.Columns = atq.fields
	if len(atq.fields) > 0 {
		_spec.Unique = atq.unique != nil && *atq.unique
	}
	return sqlgraph.CountNodes(ctx, atq.driver, _spec)
}

func (atq *AgentTaskQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := atq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (atq *AgentTaskQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   agenttask.Table,
			Columns: agenttask.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: agenttask.FieldID,
			},
		},
		From:   atq.sql,
		Unique: true,
	}
	if unique := atq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := atq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, agenttask.FieldID)
		for i := range fields {
			if fields[i] != agenttask.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := atq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := atq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := atq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := atq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (atq *AgentTaskQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(atq.driver.Dialect())
	t1 := builder.Table(agenttask.Table)
	columns := atq.fields
	if len(columns) == 0 {
		columns = agenttask.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if atq.sql != nil {
		selector = atq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if atq.unique != nil && *atq.unique {
		selector.Distinct()
	}
	for _, p := range atq.predicates {
		p(selector)
	}
	for _, p := range atq.order {
		p(selector)
	}
	if offset := atq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := atq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AgentTaskGroupBy is the group-by builder for AgentTask entities.
type AgentTaskGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (atgb *AgentTaskGroupBy) Aggregate(fns ...AggregateFunc) *AgentTaskGroupBy {
	atgb.fns = append(atgb.fns, fns...)
	return atgb
}

// Scan applies the group-by query and scans the result into the given value.
func (atgb *AgentTaskGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := atgb.path(ctx)
	if err != nil {
		return err
	}
	atgb.sql = query
	return atgb.sqlScan(ctx, v)
}

func (atgb *AgentTaskGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range atgb.fields {
		if !agenttask.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := atgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := atgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (atgb *AgentTaskGroupBy) sqlQuery() *sql.Selector {
	selector := atgb.sql.Select()
	aggregation := make([]string, 0, len(atgb.fns))
	for _, fn := range atgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(atgb.fields)+len(atgb.fns))
		for _, f := range atgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(atgb.fields...)...)
}

// AgentTaskSelect is the builder for selecting fields of AgentTask entities.
type AgentTaskSelect struct {
	*AgentTaskQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (ats *AgentTaskSelect) Scan(ctx context.Context, v interface{}) error {
	if err := ats.prepareQuery(ctx); err != nil {
		return err
	}
	ats.sql = ats.AgentTaskQuery.sqlQuery(ctx)
	return ats.sqlScan(ctx, v)
}

func (ats *AgentTaskSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := ats.sql.Query()
	if err := ats.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
