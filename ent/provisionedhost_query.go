// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"

	"github.com/facebook/ent/dialect/sql"
	"github.com/facebook/ent/dialect/sql/sqlgraph"
	"github.com/facebook/ent/schema/field"
	"github.com/gen0cide/laforge/ent/agentstatus"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/gen0cide/laforge/ent/status"
)

// ProvisionedHostQuery is the builder for querying ProvisionedHost entities.
type ProvisionedHostQuery struct {
	config
	limit      *int
	offset     *int
	order      []OrderFunc
	predicates []predicate.ProvisionedHost
	// eager-loading edges.
	withStatus             *StatusQuery
	withProvisionedNetwork *ProvisionedNetworkQuery
	withHost               *HostQuery
	withProvisionedSteps   *ProvisioningStepQuery
	withAgentStatus        *AgentStatusQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the builder.
func (phq *ProvisionedHostQuery) Where(ps ...predicate.ProvisionedHost) *ProvisionedHostQuery {
	phq.predicates = append(phq.predicates, ps...)
	return phq
}

// Limit adds a limit step to the query.
func (phq *ProvisionedHostQuery) Limit(limit int) *ProvisionedHostQuery {
	phq.limit = &limit
	return phq
}

// Offset adds an offset step to the query.
func (phq *ProvisionedHostQuery) Offset(offset int) *ProvisionedHostQuery {
	phq.offset = &offset
	return phq
}

// Order adds an order step to the query.
func (phq *ProvisionedHostQuery) Order(o ...OrderFunc) *ProvisionedHostQuery {
	phq.order = append(phq.order, o...)
	return phq
}

// QueryStatus chains the current query on the status edge.
func (phq *ProvisionedHostQuery) QueryStatus() *StatusQuery {
	query := &StatusQuery{config: phq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := phq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionedhost.Table, provisionedhost.FieldID, selector),
			sqlgraph.To(status.Table, status.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, provisionedhost.StatusTable, provisionedhost.StatusColumn),
		)
		fromU = sqlgraph.SetNeighbors(phq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisionedNetwork chains the current query on the provisioned_network edge.
func (phq *ProvisionedHostQuery) QueryProvisionedNetwork() *ProvisionedNetworkQuery {
	query := &ProvisionedNetworkQuery{config: phq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := phq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionedhost.Table, provisionedhost.FieldID, selector),
			sqlgraph.To(provisionednetwork.Table, provisionednetwork.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, provisionedhost.ProvisionedNetworkTable, provisionedhost.ProvisionedNetworkPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(phq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryHost chains the current query on the host edge.
func (phq *ProvisionedHostQuery) QueryHost() *HostQuery {
	query := &HostQuery{config: phq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := phq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionedhost.Table, provisionedhost.FieldID, selector),
			sqlgraph.To(host.Table, host.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, provisionedhost.HostTable, provisionedhost.HostColumn),
		)
		fromU = sqlgraph.SetNeighbors(phq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisionedSteps chains the current query on the provisioned_steps edge.
func (phq *ProvisionedHostQuery) QueryProvisionedSteps() *ProvisioningStepQuery {
	query := &ProvisioningStepQuery{config: phq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := phq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionedhost.Table, provisionedhost.FieldID, selector),
			sqlgraph.To(provisioningstep.Table, provisioningstep.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, provisionedhost.ProvisionedStepsTable, provisionedhost.ProvisionedStepsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(phq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryAgentStatus chains the current query on the agent_status edge.
func (phq *ProvisionedHostQuery) QueryAgentStatus() *AgentStatusQuery {
	query := &AgentStatusQuery{config: phq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := phq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionedhost.Table, provisionedhost.FieldID, selector),
			sqlgraph.To(agentstatus.Table, agentstatus.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, provisionedhost.AgentStatusTable, provisionedhost.AgentStatusPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(phq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first ProvisionedHost entity in the query. Returns *NotFoundError when no provisionedhost was found.
func (phq *ProvisionedHostQuery) First(ctx context.Context) (*ProvisionedHost, error) {
	nodes, err := phq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{provisionedhost.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (phq *ProvisionedHostQuery) FirstX(ctx context.Context) *ProvisionedHost {
	node, err := phq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first ProvisionedHost id in the query. Returns *NotFoundError when no id was found.
func (phq *ProvisionedHostQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = phq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{provisionedhost.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (phq *ProvisionedHostQuery) FirstIDX(ctx context.Context) int {
	id, err := phq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns the only ProvisionedHost entity in the query, returns an error if not exactly one entity was returned.
func (phq *ProvisionedHostQuery) Only(ctx context.Context) (*ProvisionedHost, error) {
	nodes, err := phq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{provisionedhost.Label}
	default:
		return nil, &NotSingularError{provisionedhost.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (phq *ProvisionedHostQuery) OnlyX(ctx context.Context) *ProvisionedHost {
	node, err := phq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID returns the only ProvisionedHost id in the query, returns an error if not exactly one id was returned.
func (phq *ProvisionedHostQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = phq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = &NotSingularError{provisionedhost.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (phq *ProvisionedHostQuery) OnlyIDX(ctx context.Context) int {
	id, err := phq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of ProvisionedHosts.
func (phq *ProvisionedHostQuery) All(ctx context.Context) ([]*ProvisionedHost, error) {
	if err := phq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return phq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (phq *ProvisionedHostQuery) AllX(ctx context.Context) []*ProvisionedHost {
	nodes, err := phq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of ProvisionedHost ids.
func (phq *ProvisionedHostQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := phq.Select(provisionedhost.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (phq *ProvisionedHostQuery) IDsX(ctx context.Context) []int {
	ids, err := phq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (phq *ProvisionedHostQuery) Count(ctx context.Context) (int, error) {
	if err := phq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return phq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (phq *ProvisionedHostQuery) CountX(ctx context.Context) int {
	count, err := phq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (phq *ProvisionedHostQuery) Exist(ctx context.Context) (bool, error) {
	if err := phq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return phq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (phq *ProvisionedHostQuery) ExistX(ctx context.Context) bool {
	exist, err := phq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the query builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (phq *ProvisionedHostQuery) Clone() *ProvisionedHostQuery {
	if phq == nil {
		return nil
	}
	return &ProvisionedHostQuery{
		config:                 phq.config,
		limit:                  phq.limit,
		offset:                 phq.offset,
		order:                  append([]OrderFunc{}, phq.order...),
		predicates:             append([]predicate.ProvisionedHost{}, phq.predicates...),
		withStatus:             phq.withStatus.Clone(),
		withProvisionedNetwork: phq.withProvisionedNetwork.Clone(),
		withHost:               phq.withHost.Clone(),
		withProvisionedSteps:   phq.withProvisionedSteps.Clone(),
		withAgentStatus:        phq.withAgentStatus.Clone(),
		// clone intermediate query.
		sql:  phq.sql.Clone(),
		path: phq.path,
	}
}

//  WithStatus tells the query-builder to eager-loads the nodes that are connected to
// the "status" edge. The optional arguments used to configure the query builder of the edge.
func (phq *ProvisionedHostQuery) WithStatus(opts ...func(*StatusQuery)) *ProvisionedHostQuery {
	query := &StatusQuery{config: phq.config}
	for _, opt := range opts {
		opt(query)
	}
	phq.withStatus = query
	return phq
}

//  WithProvisionedNetwork tells the query-builder to eager-loads the nodes that are connected to
// the "provisioned_network" edge. The optional arguments used to configure the query builder of the edge.
func (phq *ProvisionedHostQuery) WithProvisionedNetwork(opts ...func(*ProvisionedNetworkQuery)) *ProvisionedHostQuery {
	query := &ProvisionedNetworkQuery{config: phq.config}
	for _, opt := range opts {
		opt(query)
	}
	phq.withProvisionedNetwork = query
	return phq
}

//  WithHost tells the query-builder to eager-loads the nodes that are connected to
// the "host" edge. The optional arguments used to configure the query builder of the edge.
func (phq *ProvisionedHostQuery) WithHost(opts ...func(*HostQuery)) *ProvisionedHostQuery {
	query := &HostQuery{config: phq.config}
	for _, opt := range opts {
		opt(query)
	}
	phq.withHost = query
	return phq
}

//  WithProvisionedSteps tells the query-builder to eager-loads the nodes that are connected to
// the "provisioned_steps" edge. The optional arguments used to configure the query builder of the edge.
func (phq *ProvisionedHostQuery) WithProvisionedSteps(opts ...func(*ProvisioningStepQuery)) *ProvisionedHostQuery {
	query := &ProvisioningStepQuery{config: phq.config}
	for _, opt := range opts {
		opt(query)
	}
	phq.withProvisionedSteps = query
	return phq
}

//  WithAgentStatus tells the query-builder to eager-loads the nodes that are connected to
// the "agent_status" edge. The optional arguments used to configure the query builder of the edge.
func (phq *ProvisionedHostQuery) WithAgentStatus(opts ...func(*AgentStatusQuery)) *ProvisionedHostQuery {
	query := &AgentStatusQuery{config: phq.config}
	for _, opt := range opts {
		opt(query)
	}
	phq.withAgentStatus = query
	return phq
}

// GroupBy used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		SubnetIP string `json:"subnet_ip,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.ProvisionedHost.Query().
//		GroupBy(provisionedhost.FieldSubnetIP).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
//
func (phq *ProvisionedHostQuery) GroupBy(field string, fields ...string) *ProvisionedHostGroupBy {
	group := &ProvisionedHostGroupBy{config: phq.config}
	group.fields = append([]string{field}, fields...)
	group.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return phq.sqlQuery(), nil
	}
	return group
}

// Select one or more fields from the given query.
//
// Example:
//
//	var v []struct {
//		SubnetIP string `json:"subnet_ip,omitempty"`
//	}
//
//	client.ProvisionedHost.Query().
//		Select(provisionedhost.FieldSubnetIP).
//		Scan(ctx, &v)
//
func (phq *ProvisionedHostQuery) Select(field string, fields ...string) *ProvisionedHostSelect {
	selector := &ProvisionedHostSelect{config: phq.config}
	selector.fields = append([]string{field}, fields...)
	selector.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := phq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return phq.sqlQuery(), nil
	}
	return selector
}

func (phq *ProvisionedHostQuery) prepareQuery(ctx context.Context) error {
	if phq.path != nil {
		prev, err := phq.path(ctx)
		if err != nil {
			return err
		}
		phq.sql = prev
	}
	return nil
}

func (phq *ProvisionedHostQuery) sqlAll(ctx context.Context) ([]*ProvisionedHost, error) {
	var (
		nodes       = []*ProvisionedHost{}
		_spec       = phq.querySpec()
		loadedTypes = [5]bool{
			phq.withStatus != nil,
			phq.withProvisionedNetwork != nil,
			phq.withHost != nil,
			phq.withProvisionedSteps != nil,
			phq.withAgentStatus != nil,
		}
	)
	_spec.ScanValues = func() []interface{} {
		node := &ProvisionedHost{config: phq.config}
		nodes = append(nodes, node)
		values := node.scanValues()
		return values
	}
	_spec.Assign = func(values ...interface{}) error {
		if len(nodes) == 0 {
			return fmt.Errorf("ent: Assign called without calling ScanValues")
		}
		node := nodes[len(nodes)-1]
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(values...)
	}
	if err := sqlgraph.QueryNodes(ctx, phq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}

	if query := phq.withStatus; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		nodeids := make(map[int]*ProvisionedHost)
		for i := range nodes {
			fks = append(fks, nodes[i].ID)
			nodeids[nodes[i].ID] = nodes[i]
			nodes[i].Edges.Status = []*Status{}
		}
		query.withFKs = true
		query.Where(predicate.Status(func(s *sql.Selector) {
			s.Where(sql.InValues(provisionedhost.StatusColumn, fks...))
		}))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			fk := n.provisioned_host_status
			if fk == nil {
				return nil, fmt.Errorf(`foreign-key "provisioned_host_status" is nil for node %v`, n.ID)
			}
			node, ok := nodeids[*fk]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "provisioned_host_status" returned %v for node %v`, *fk, n.ID)
			}
			node.Edges.Status = append(node.Edges.Status, n)
		}
	}

	if query := phq.withProvisionedNetwork; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		ids := make(map[int]*ProvisionedHost, len(nodes))
		for _, node := range nodes {
			ids[node.ID] = node
			fks = append(fks, node.ID)
			node.Edges.ProvisionedNetwork = []*ProvisionedNetwork{}
		}
		var (
			edgeids []int
			edges   = make(map[int][]*ProvisionedHost)
		)
		_spec := &sqlgraph.EdgeQuerySpec{
			Edge: &sqlgraph.EdgeSpec{
				Inverse: false,
				Table:   provisionedhost.ProvisionedNetworkTable,
				Columns: provisionedhost.ProvisionedNetworkPrimaryKey,
			},
			Predicate: func(s *sql.Selector) {
				s.Where(sql.InValues(provisionedhost.ProvisionedNetworkPrimaryKey[0], fks...))
			},

			ScanValues: func() [2]interface{} {
				return [2]interface{}{&sql.NullInt64{}, &sql.NullInt64{}}
			},
			Assign: func(out, in interface{}) error {
				eout, ok := out.(*sql.NullInt64)
				if !ok || eout == nil {
					return fmt.Errorf("unexpected id value for edge-out")
				}
				ein, ok := in.(*sql.NullInt64)
				if !ok || ein == nil {
					return fmt.Errorf("unexpected id value for edge-in")
				}
				outValue := int(eout.Int64)
				inValue := int(ein.Int64)
				node, ok := ids[outValue]
				if !ok {
					return fmt.Errorf("unexpected node id in edges: %v", outValue)
				}
				edgeids = append(edgeids, inValue)
				edges[inValue] = append(edges[inValue], node)
				return nil
			},
		}
		if err := sqlgraph.QueryEdges(ctx, phq.driver, _spec); err != nil {
			return nil, fmt.Errorf(`query edges "provisioned_network": %v`, err)
		}
		query.Where(provisionednetwork.IDIn(edgeids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := edges[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected "provisioned_network" node returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.ProvisionedNetwork = append(nodes[i].Edges.ProvisionedNetwork, n)
			}
		}
	}

	if query := phq.withHost; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		nodeids := make(map[int]*ProvisionedHost)
		for i := range nodes {
			fks = append(fks, nodes[i].ID)
			nodeids[nodes[i].ID] = nodes[i]
			nodes[i].Edges.Host = []*Host{}
		}
		query.withFKs = true
		query.Where(predicate.Host(func(s *sql.Selector) {
			s.Where(sql.InValues(provisionedhost.HostColumn, fks...))
		}))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			fk := n.provisioned_host_host
			if fk == nil {
				return nil, fmt.Errorf(`foreign-key "provisioned_host_host" is nil for node %v`, n.ID)
			}
			node, ok := nodeids[*fk]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "provisioned_host_host" returned %v for node %v`, *fk, n.ID)
			}
			node.Edges.Host = append(node.Edges.Host, n)
		}
	}

	if query := phq.withProvisionedSteps; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		ids := make(map[int]*ProvisionedHost, len(nodes))
		for _, node := range nodes {
			ids[node.ID] = node
			fks = append(fks, node.ID)
			node.Edges.ProvisionedSteps = []*ProvisioningStep{}
		}
		var (
			edgeids []int
			edges   = make(map[int][]*ProvisionedHost)
		)
		_spec := &sqlgraph.EdgeQuerySpec{
			Edge: &sqlgraph.EdgeSpec{
				Inverse: true,
				Table:   provisionedhost.ProvisionedStepsTable,
				Columns: provisionedhost.ProvisionedStepsPrimaryKey,
			},
			Predicate: func(s *sql.Selector) {
				s.Where(sql.InValues(provisionedhost.ProvisionedStepsPrimaryKey[1], fks...))
			},

			ScanValues: func() [2]interface{} {
				return [2]interface{}{&sql.NullInt64{}, &sql.NullInt64{}}
			},
			Assign: func(out, in interface{}) error {
				eout, ok := out.(*sql.NullInt64)
				if !ok || eout == nil {
					return fmt.Errorf("unexpected id value for edge-out")
				}
				ein, ok := in.(*sql.NullInt64)
				if !ok || ein == nil {
					return fmt.Errorf("unexpected id value for edge-in")
				}
				outValue := int(eout.Int64)
				inValue := int(ein.Int64)
				node, ok := ids[outValue]
				if !ok {
					return fmt.Errorf("unexpected node id in edges: %v", outValue)
				}
				edgeids = append(edgeids, inValue)
				edges[inValue] = append(edges[inValue], node)
				return nil
			},
		}
		if err := sqlgraph.QueryEdges(ctx, phq.driver, _spec); err != nil {
			return nil, fmt.Errorf(`query edges "provisioned_steps": %v`, err)
		}
		query.Where(provisioningstep.IDIn(edgeids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := edges[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected "provisioned_steps" node returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.ProvisionedSteps = append(nodes[i].Edges.ProvisionedSteps, n)
			}
		}
	}

	if query := phq.withAgentStatus; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		ids := make(map[int]*ProvisionedHost, len(nodes))
		for _, node := range nodes {
			ids[node.ID] = node
			fks = append(fks, node.ID)
			node.Edges.AgentStatus = []*AgentStatus{}
		}
		var (
			edgeids []int
			edges   = make(map[int][]*ProvisionedHost)
		)
		_spec := &sqlgraph.EdgeQuerySpec{
			Edge: &sqlgraph.EdgeSpec{
				Inverse: true,
				Table:   provisionedhost.AgentStatusTable,
				Columns: provisionedhost.AgentStatusPrimaryKey,
			},
			Predicate: func(s *sql.Selector) {
				s.Where(sql.InValues(provisionedhost.AgentStatusPrimaryKey[1], fks...))
			},

			ScanValues: func() [2]interface{} {
				return [2]interface{}{&sql.NullInt64{}, &sql.NullInt64{}}
			},
			Assign: func(out, in interface{}) error {
				eout, ok := out.(*sql.NullInt64)
				if !ok || eout == nil {
					return fmt.Errorf("unexpected id value for edge-out")
				}
				ein, ok := in.(*sql.NullInt64)
				if !ok || ein == nil {
					return fmt.Errorf("unexpected id value for edge-in")
				}
				outValue := int(eout.Int64)
				inValue := int(ein.Int64)
				node, ok := ids[outValue]
				if !ok {
					return fmt.Errorf("unexpected node id in edges: %v", outValue)
				}
				edgeids = append(edgeids, inValue)
				edges[inValue] = append(edges[inValue], node)
				return nil
			},
		}
		if err := sqlgraph.QueryEdges(ctx, phq.driver, _spec); err != nil {
			return nil, fmt.Errorf(`query edges "agent_status": %v`, err)
		}
		query.Where(agentstatus.IDIn(edgeids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := edges[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected "agent_status" node returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.AgentStatus = append(nodes[i].Edges.AgentStatus, n)
			}
		}
	}

	return nodes, nil
}

func (phq *ProvisionedHostQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := phq.querySpec()
	return sqlgraph.CountNodes(ctx, phq.driver, _spec)
}

func (phq *ProvisionedHostQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := phq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %v", err)
	}
	return n > 0, nil
}

func (phq *ProvisionedHostQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   provisionedhost.Table,
			Columns: provisionedhost.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: provisionedhost.FieldID,
			},
		},
		From:   phq.sql,
		Unique: true,
	}
	if ps := phq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := phq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := phq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := phq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector, provisionedhost.ValidColumn)
			}
		}
	}
	return _spec
}

func (phq *ProvisionedHostQuery) sqlQuery() *sql.Selector {
	builder := sql.Dialect(phq.driver.Dialect())
	t1 := builder.Table(provisionedhost.Table)
	selector := builder.Select(t1.Columns(provisionedhost.Columns...)...).From(t1)
	if phq.sql != nil {
		selector = phq.sql
		selector.Select(selector.Columns(provisionedhost.Columns...)...)
	}
	for _, p := range phq.predicates {
		p(selector)
	}
	for _, p := range phq.order {
		p(selector, provisionedhost.ValidColumn)
	}
	if offset := phq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := phq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ProvisionedHostGroupBy is the builder for group-by ProvisionedHost entities.
type ProvisionedHostGroupBy struct {
	config
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (phgb *ProvisionedHostGroupBy) Aggregate(fns ...AggregateFunc) *ProvisionedHostGroupBy {
	phgb.fns = append(phgb.fns, fns...)
	return phgb
}

// Scan applies the group-by query and scan the result into the given value.
func (phgb *ProvisionedHostGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := phgb.path(ctx)
	if err != nil {
		return err
	}
	phgb.sql = query
	return phgb.sqlScan(ctx, v)
}

// ScanX is like Scan, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) ScanX(ctx context.Context, v interface{}) {
	if err := phgb.Scan(ctx, v); err != nil {
		panic(err)
	}
}

// Strings returns list of strings from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Strings(ctx context.Context) ([]string, error) {
	if len(phgb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostGroupBy.Strings is not achievable when grouping more than 1 field")
	}
	var v []string
	if err := phgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// StringsX is like Strings, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) StringsX(ctx context.Context) []string {
	v, err := phgb.Strings(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns a single string from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) String(ctx context.Context) (_ string, err error) {
	var v []string
	if v, err = phgb.Strings(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostGroupBy.Strings returned %d results when one was expected", len(v))
	}
	return
}

// StringX is like String, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) StringX(ctx context.Context) string {
	v, err := phgb.String(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Ints returns list of ints from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Ints(ctx context.Context) ([]int, error) {
	if len(phgb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostGroupBy.Ints is not achievable when grouping more than 1 field")
	}
	var v []int
	if err := phgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// IntsX is like Ints, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) IntsX(ctx context.Context) []int {
	v, err := phgb.Ints(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Int returns a single int from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Int(ctx context.Context) (_ int, err error) {
	var v []int
	if v, err = phgb.Ints(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostGroupBy.Ints returned %d results when one was expected", len(v))
	}
	return
}

// IntX is like Int, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) IntX(ctx context.Context) int {
	v, err := phgb.Int(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64s returns list of float64s from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Float64s(ctx context.Context) ([]float64, error) {
	if len(phgb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostGroupBy.Float64s is not achievable when grouping more than 1 field")
	}
	var v []float64
	if err := phgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Float64sX is like Float64s, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) Float64sX(ctx context.Context) []float64 {
	v, err := phgb.Float64s(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64 returns a single float64 from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Float64(ctx context.Context) (_ float64, err error) {
	var v []float64
	if v, err = phgb.Float64s(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostGroupBy.Float64s returned %d results when one was expected", len(v))
	}
	return
}

// Float64X is like Float64, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) Float64X(ctx context.Context) float64 {
	v, err := phgb.Float64(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bools returns list of bools from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Bools(ctx context.Context) ([]bool, error) {
	if len(phgb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostGroupBy.Bools is not achievable when grouping more than 1 field")
	}
	var v []bool
	if err := phgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// BoolsX is like Bools, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) BoolsX(ctx context.Context) []bool {
	v, err := phgb.Bools(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bool returns a single bool from group-by. It is only allowed when querying group-by with one field.
func (phgb *ProvisionedHostGroupBy) Bool(ctx context.Context) (_ bool, err error) {
	var v []bool
	if v, err = phgb.Bools(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostGroupBy.Bools returned %d results when one was expected", len(v))
	}
	return
}

// BoolX is like Bool, but panics if an error occurs.
func (phgb *ProvisionedHostGroupBy) BoolX(ctx context.Context) bool {
	v, err := phgb.Bool(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (phgb *ProvisionedHostGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range phgb.fields {
		if !provisionedhost.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := phgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := phgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (phgb *ProvisionedHostGroupBy) sqlQuery() *sql.Selector {
	selector := phgb.sql
	columns := make([]string, 0, len(phgb.fields)+len(phgb.fns))
	columns = append(columns, phgb.fields...)
	for _, fn := range phgb.fns {
		columns = append(columns, fn(selector, provisionedhost.ValidColumn))
	}
	return selector.Select(columns...).GroupBy(phgb.fields...)
}

// ProvisionedHostSelect is the builder for select fields of ProvisionedHost entities.
type ProvisionedHostSelect struct {
	config
	fields []string
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Scan applies the selector query and scan the result into the given value.
func (phs *ProvisionedHostSelect) Scan(ctx context.Context, v interface{}) error {
	query, err := phs.path(ctx)
	if err != nil {
		return err
	}
	phs.sql = query
	return phs.sqlScan(ctx, v)
}

// ScanX is like Scan, but panics if an error occurs.
func (phs *ProvisionedHostSelect) ScanX(ctx context.Context, v interface{}) {
	if err := phs.Scan(ctx, v); err != nil {
		panic(err)
	}
}

// Strings returns list of strings from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Strings(ctx context.Context) ([]string, error) {
	if len(phs.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostSelect.Strings is not achievable when selecting more than 1 field")
	}
	var v []string
	if err := phs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// StringsX is like Strings, but panics if an error occurs.
func (phs *ProvisionedHostSelect) StringsX(ctx context.Context) []string {
	v, err := phs.Strings(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns a single string from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) String(ctx context.Context) (_ string, err error) {
	var v []string
	if v, err = phs.Strings(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostSelect.Strings returned %d results when one was expected", len(v))
	}
	return
}

// StringX is like String, but panics if an error occurs.
func (phs *ProvisionedHostSelect) StringX(ctx context.Context) string {
	v, err := phs.String(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Ints returns list of ints from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Ints(ctx context.Context) ([]int, error) {
	if len(phs.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostSelect.Ints is not achievable when selecting more than 1 field")
	}
	var v []int
	if err := phs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// IntsX is like Ints, but panics if an error occurs.
func (phs *ProvisionedHostSelect) IntsX(ctx context.Context) []int {
	v, err := phs.Ints(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Int returns a single int from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Int(ctx context.Context) (_ int, err error) {
	var v []int
	if v, err = phs.Ints(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostSelect.Ints returned %d results when one was expected", len(v))
	}
	return
}

// IntX is like Int, but panics if an error occurs.
func (phs *ProvisionedHostSelect) IntX(ctx context.Context) int {
	v, err := phs.Int(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64s returns list of float64s from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Float64s(ctx context.Context) ([]float64, error) {
	if len(phs.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostSelect.Float64s is not achievable when selecting more than 1 field")
	}
	var v []float64
	if err := phs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Float64sX is like Float64s, but panics if an error occurs.
func (phs *ProvisionedHostSelect) Float64sX(ctx context.Context) []float64 {
	v, err := phs.Float64s(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64 returns a single float64 from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Float64(ctx context.Context) (_ float64, err error) {
	var v []float64
	if v, err = phs.Float64s(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostSelect.Float64s returned %d results when one was expected", len(v))
	}
	return
}

// Float64X is like Float64, but panics if an error occurs.
func (phs *ProvisionedHostSelect) Float64X(ctx context.Context) float64 {
	v, err := phs.Float64(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bools returns list of bools from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Bools(ctx context.Context) ([]bool, error) {
	if len(phs.fields) > 1 {
		return nil, errors.New("ent: ProvisionedHostSelect.Bools is not achievable when selecting more than 1 field")
	}
	var v []bool
	if err := phs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// BoolsX is like Bools, but panics if an error occurs.
func (phs *ProvisionedHostSelect) BoolsX(ctx context.Context) []bool {
	v, err := phs.Bools(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bool returns a single bool from selector. It is only allowed when selecting one field.
func (phs *ProvisionedHostSelect) Bool(ctx context.Context) (_ bool, err error) {
	var v []bool
	if v, err = phs.Bools(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionedhost.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedHostSelect.Bools returned %d results when one was expected", len(v))
	}
	return
}

// BoolX is like Bool, but panics if an error occurs.
func (phs *ProvisionedHostSelect) BoolX(ctx context.Context) bool {
	v, err := phs.Bool(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (phs *ProvisionedHostSelect) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range phs.fields {
		if !provisionedhost.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for selection", f)}
		}
	}
	rows := &sql.Rows{}
	query, args := phs.sqlQuery().Query()
	if err := phs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (phs *ProvisionedHostSelect) sqlQuery() sql.Querier {
	selector := phs.sql
	selector.Select(selector.Columns(phs.fields...)...)
	return selector
}
