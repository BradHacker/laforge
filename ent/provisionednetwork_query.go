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
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/network"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/gen0cide/laforge/ent/team"
)

// ProvisionedNetworkQuery is the builder for querying ProvisionedNetwork entities.
type ProvisionedNetworkQuery struct {
	config
	limit      *int
	offset     *int
	order      []OrderFunc
	unique     []string
	predicates []predicate.ProvisionedNetwork
	// eager-loading edges.
	withStatus                   *StatusQuery
	withNetwork                  *NetworkQuery
	withBuild                    *BuildQuery
	withProvisionedNetworkToTeam *TeamQuery
	withProvisionedHosts         *ProvisionedHostQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the builder.
func (pnq *ProvisionedNetworkQuery) Where(ps ...predicate.ProvisionedNetwork) *ProvisionedNetworkQuery {
	pnq.predicates = append(pnq.predicates, ps...)
	return pnq
}

// Limit adds a limit step to the query.
func (pnq *ProvisionedNetworkQuery) Limit(limit int) *ProvisionedNetworkQuery {
	pnq.limit = &limit
	return pnq
}

// Offset adds an offset step to the query.
func (pnq *ProvisionedNetworkQuery) Offset(offset int) *ProvisionedNetworkQuery {
	pnq.offset = &offset
	return pnq
}

// Order adds an order step to the query.
func (pnq *ProvisionedNetworkQuery) Order(o ...OrderFunc) *ProvisionedNetworkQuery {
	pnq.order = append(pnq.order, o...)
	return pnq
}

// QueryStatus chains the current query on the status edge.
func (pnq *ProvisionedNetworkQuery) QueryStatus() *StatusQuery {
	query := &StatusQuery{config: pnq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pnq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionednetwork.Table, provisionednetwork.FieldID, selector),
			sqlgraph.To(status.Table, status.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, provisionednetwork.StatusTable, provisionednetwork.StatusColumn),
		)
		fromU = sqlgraph.SetNeighbors(pnq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryNetwork chains the current query on the network edge.
func (pnq *ProvisionedNetworkQuery) QueryNetwork() *NetworkQuery {
	query := &NetworkQuery{config: pnq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pnq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionednetwork.Table, provisionednetwork.FieldID, selector),
			sqlgraph.To(network.Table, network.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, provisionednetwork.NetworkTable, provisionednetwork.NetworkColumn),
		)
		fromU = sqlgraph.SetNeighbors(pnq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryBuild chains the current query on the build edge.
func (pnq *ProvisionedNetworkQuery) QueryBuild() *BuildQuery {
	query := &BuildQuery{config: pnq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pnq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionednetwork.Table, provisionednetwork.FieldID, selector),
			sqlgraph.To(build.Table, build.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, provisionednetwork.BuildTable, provisionednetwork.BuildColumn),
		)
		fromU = sqlgraph.SetNeighbors(pnq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisionedNetworkToTeam chains the current query on the ProvisionedNetworkToTeam edge.
func (pnq *ProvisionedNetworkQuery) QueryProvisionedNetworkToTeam() *TeamQuery {
	query := &TeamQuery{config: pnq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pnq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionednetwork.Table, provisionednetwork.FieldID, selector),
			sqlgraph.To(team.Table, team.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, provisionednetwork.ProvisionedNetworkToTeamTable, provisionednetwork.ProvisionedNetworkToTeamPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(pnq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryProvisionedHosts chains the current query on the provisioned_hosts edge.
func (pnq *ProvisionedNetworkQuery) QueryProvisionedHosts() *ProvisionedHostQuery {
	query := &ProvisionedHostQuery{config: pnq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := pnq.sqlQuery()
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(provisionednetwork.Table, provisionednetwork.FieldID, selector),
			sqlgraph.To(provisionedhost.Table, provisionedhost.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, provisionednetwork.ProvisionedHostsTable, provisionednetwork.ProvisionedHostsPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(pnq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first ProvisionedNetwork entity in the query. Returns *NotFoundError when no provisionednetwork was found.
func (pnq *ProvisionedNetworkQuery) First(ctx context.Context) (*ProvisionedNetwork, error) {
	nodes, err := pnq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{provisionednetwork.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) FirstX(ctx context.Context) *ProvisionedNetwork {
	node, err := pnq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first ProvisionedNetwork id in the query. Returns *NotFoundError when no id was found.
func (pnq *ProvisionedNetworkQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = pnq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{provisionednetwork.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) FirstIDX(ctx context.Context) int {
	id, err := pnq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns the only ProvisionedNetwork entity in the query, returns an error if not exactly one entity was returned.
func (pnq *ProvisionedNetworkQuery) Only(ctx context.Context) (*ProvisionedNetwork, error) {
	nodes, err := pnq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{provisionednetwork.Label}
	default:
		return nil, &NotSingularError{provisionednetwork.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) OnlyX(ctx context.Context) *ProvisionedNetwork {
	node, err := pnq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID returns the only ProvisionedNetwork id in the query, returns an error if not exactly one id was returned.
func (pnq *ProvisionedNetworkQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = pnq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = &NotSingularError{provisionednetwork.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) OnlyIDX(ctx context.Context) int {
	id, err := pnq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of ProvisionedNetworks.
func (pnq *ProvisionedNetworkQuery) All(ctx context.Context) ([]*ProvisionedNetwork, error) {
	if err := pnq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return pnq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) AllX(ctx context.Context) []*ProvisionedNetwork {
	nodes, err := pnq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of ProvisionedNetwork ids.
func (pnq *ProvisionedNetworkQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := pnq.Select(provisionednetwork.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) IDsX(ctx context.Context) []int {
	ids, err := pnq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (pnq *ProvisionedNetworkQuery) Count(ctx context.Context) (int, error) {
	if err := pnq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return pnq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) CountX(ctx context.Context) int {
	count, err := pnq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (pnq *ProvisionedNetworkQuery) Exist(ctx context.Context) (bool, error) {
	if err := pnq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return pnq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (pnq *ProvisionedNetworkQuery) ExistX(ctx context.Context) bool {
	exist, err := pnq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the query builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (pnq *ProvisionedNetworkQuery) Clone() *ProvisionedNetworkQuery {
	if pnq == nil {
		return nil
	}
	return &ProvisionedNetworkQuery{
		config:                       pnq.config,
		limit:                        pnq.limit,
		offset:                       pnq.offset,
		order:                        append([]OrderFunc{}, pnq.order...),
		unique:                       append([]string{}, pnq.unique...),
		predicates:                   append([]predicate.ProvisionedNetwork{}, pnq.predicates...),
		withStatus:                   pnq.withStatus.Clone(),
		withNetwork:                  pnq.withNetwork.Clone(),
		withBuild:                    pnq.withBuild.Clone(),
		withProvisionedNetworkToTeam: pnq.withProvisionedNetworkToTeam.Clone(),
		withProvisionedHosts:         pnq.withProvisionedHosts.Clone(),
		// clone intermediate query.
		sql:  pnq.sql.Clone(),
		path: pnq.path,
	}
}

//  WithStatus tells the query-builder to eager-loads the nodes that are connected to
// the "status" edge. The optional arguments used to configure the query builder of the edge.
func (pnq *ProvisionedNetworkQuery) WithStatus(opts ...func(*StatusQuery)) *ProvisionedNetworkQuery {
	query := &StatusQuery{config: pnq.config}
	for _, opt := range opts {
		opt(query)
	}
	pnq.withStatus = query
	return pnq
}

//  WithNetwork tells the query-builder to eager-loads the nodes that are connected to
// the "network" edge. The optional arguments used to configure the query builder of the edge.
func (pnq *ProvisionedNetworkQuery) WithNetwork(opts ...func(*NetworkQuery)) *ProvisionedNetworkQuery {
	query := &NetworkQuery{config: pnq.config}
	for _, opt := range opts {
		opt(query)
	}
	pnq.withNetwork = query
	return pnq
}

//  WithBuild tells the query-builder to eager-loads the nodes that are connected to
// the "build" edge. The optional arguments used to configure the query builder of the edge.
func (pnq *ProvisionedNetworkQuery) WithBuild(opts ...func(*BuildQuery)) *ProvisionedNetworkQuery {
	query := &BuildQuery{config: pnq.config}
	for _, opt := range opts {
		opt(query)
	}
	pnq.withBuild = query
	return pnq
}

//  WithProvisionedNetworkToTeam tells the query-builder to eager-loads the nodes that are connected to
// the "ProvisionedNetworkToTeam" edge. The optional arguments used to configure the query builder of the edge.
func (pnq *ProvisionedNetworkQuery) WithProvisionedNetworkToTeam(opts ...func(*TeamQuery)) *ProvisionedNetworkQuery {
	query := &TeamQuery{config: pnq.config}
	for _, opt := range opts {
		opt(query)
	}
	pnq.withProvisionedNetworkToTeam = query
	return pnq
}

//  WithProvisionedHosts tells the query-builder to eager-loads the nodes that are connected to
// the "provisioned_hosts" edge. The optional arguments used to configure the query builder of the edge.
func (pnq *ProvisionedNetworkQuery) WithProvisionedHosts(opts ...func(*ProvisionedHostQuery)) *ProvisionedNetworkQuery {
	query := &ProvisionedHostQuery{config: pnq.config}
	for _, opt := range opts {
		opt(query)
	}
	pnq.withProvisionedHosts = query
	return pnq
}

// GroupBy used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.ProvisionedNetwork.Query().
//		GroupBy(provisionednetwork.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
//
func (pnq *ProvisionedNetworkQuery) GroupBy(field string, fields ...string) *ProvisionedNetworkGroupBy {
	group := &ProvisionedNetworkGroupBy{config: pnq.config}
	group.fields = append([]string{field}, fields...)
	group.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return pnq.sqlQuery(), nil
	}
	return group
}

// Select one or more fields from the given query.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//	}
//
//	client.ProvisionedNetwork.Query().
//		Select(provisionednetwork.FieldName).
//		Scan(ctx, &v)
//
func (pnq *ProvisionedNetworkQuery) Select(field string, fields ...string) *ProvisionedNetworkSelect {
	selector := &ProvisionedNetworkSelect{config: pnq.config}
	selector.fields = append([]string{field}, fields...)
	selector.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := pnq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return pnq.sqlQuery(), nil
	}
	return selector
}

func (pnq *ProvisionedNetworkQuery) prepareQuery(ctx context.Context) error {
	if pnq.path != nil {
		prev, err := pnq.path(ctx)
		if err != nil {
			return err
		}
		pnq.sql = prev
	}
	return nil
}

func (pnq *ProvisionedNetworkQuery) sqlAll(ctx context.Context) ([]*ProvisionedNetwork, error) {
	var (
		nodes       = []*ProvisionedNetwork{}
		_spec       = pnq.querySpec()
		loadedTypes = [5]bool{
			pnq.withStatus != nil,
			pnq.withNetwork != nil,
			pnq.withBuild != nil,
			pnq.withProvisionedNetworkToTeam != nil,
			pnq.withProvisionedHosts != nil,
		}
	)
	_spec.ScanValues = func() []interface{} {
		node := &ProvisionedNetwork{config: pnq.config}
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
	if err := sqlgraph.QueryNodes(ctx, pnq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}

	if query := pnq.withStatus; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		nodeids := make(map[int]*ProvisionedNetwork)
		for i := range nodes {
			fks = append(fks, nodes[i].ID)
			nodeids[nodes[i].ID] = nodes[i]
			nodes[i].Edges.Status = []*Status{}
		}
		query.withFKs = true
		query.Where(predicate.Status(func(s *sql.Selector) {
			s.Where(sql.InValues(provisionednetwork.StatusColumn, fks...))
		}))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			fk := n.provisioned_network_status
			if fk == nil {
				return nil, fmt.Errorf(`foreign-key "provisioned_network_status" is nil for node %v`, n.ID)
			}
			node, ok := nodeids[*fk]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "provisioned_network_status" returned %v for node %v`, *fk, n.ID)
			}
			node.Edges.Status = append(node.Edges.Status, n)
		}
	}

	if query := pnq.withNetwork; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		nodeids := make(map[int]*ProvisionedNetwork)
		for i := range nodes {
			fks = append(fks, nodes[i].ID)
			nodeids[nodes[i].ID] = nodes[i]
			nodes[i].Edges.Network = []*Network{}
		}
		query.withFKs = true
		query.Where(predicate.Network(func(s *sql.Selector) {
			s.Where(sql.InValues(provisionednetwork.NetworkColumn, fks...))
		}))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			fk := n.provisioned_network_network
			if fk == nil {
				return nil, fmt.Errorf(`foreign-key "provisioned_network_network" is nil for node %v`, n.ID)
			}
			node, ok := nodeids[*fk]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "provisioned_network_network" returned %v for node %v`, *fk, n.ID)
			}
			node.Edges.Network = append(node.Edges.Network, n)
		}
	}

	if query := pnq.withBuild; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		nodeids := make(map[int]*ProvisionedNetwork)
		for i := range nodes {
			fks = append(fks, nodes[i].ID)
			nodeids[nodes[i].ID] = nodes[i]
			nodes[i].Edges.Build = []*Build{}
		}
		query.withFKs = true
		query.Where(predicate.Build(func(s *sql.Selector) {
			s.Where(sql.InValues(provisionednetwork.BuildColumn, fks...))
		}))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			fk := n.provisioned_network_build
			if fk == nil {
				return nil, fmt.Errorf(`foreign-key "provisioned_network_build" is nil for node %v`, n.ID)
			}
			node, ok := nodeids[*fk]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "provisioned_network_build" returned %v for node %v`, *fk, n.ID)
			}
			node.Edges.Build = append(node.Edges.Build, n)
		}
	}

	if query := pnq.withProvisionedNetworkToTeam; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		ids := make(map[int]*ProvisionedNetwork, len(nodes))
		for _, node := range nodes {
			ids[node.ID] = node
			fks = append(fks, node.ID)
			node.Edges.ProvisionedNetworkToTeam = []*Team{}
		}
		var (
			edgeids []int
			edges   = make(map[int][]*ProvisionedNetwork)
		)
		_spec := &sqlgraph.EdgeQuerySpec{
			Edge: &sqlgraph.EdgeSpec{
				Inverse: false,
				Table:   provisionednetwork.ProvisionedNetworkToTeamTable,
				Columns: provisionednetwork.ProvisionedNetworkToTeamPrimaryKey,
			},
			Predicate: func(s *sql.Selector) {
				s.Where(sql.InValues(provisionednetwork.ProvisionedNetworkToTeamPrimaryKey[0], fks...))
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
		if err := sqlgraph.QueryEdges(ctx, pnq.driver, _spec); err != nil {
			return nil, fmt.Errorf(`query edges "ProvisionedNetworkToTeam": %v`, err)
		}
		query.Where(team.IDIn(edgeids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := edges[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected "ProvisionedNetworkToTeam" node returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.ProvisionedNetworkToTeam = append(nodes[i].Edges.ProvisionedNetworkToTeam, n)
			}
		}
	}

	if query := pnq.withProvisionedHosts; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		ids := make(map[int]*ProvisionedNetwork, len(nodes))
		for _, node := range nodes {
			ids[node.ID] = node
			fks = append(fks, node.ID)
			node.Edges.ProvisionedHosts = []*ProvisionedHost{}
		}
		var (
			edgeids []int
			edges   = make(map[int][]*ProvisionedNetwork)
		)
		_spec := &sqlgraph.EdgeQuerySpec{
			Edge: &sqlgraph.EdgeSpec{
				Inverse: true,
				Table:   provisionednetwork.ProvisionedHostsTable,
				Columns: provisionednetwork.ProvisionedHostsPrimaryKey,
			},
			Predicate: func(s *sql.Selector) {
				s.Where(sql.InValues(provisionednetwork.ProvisionedHostsPrimaryKey[1], fks...))
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
		if err := sqlgraph.QueryEdges(ctx, pnq.driver, _spec); err != nil {
			return nil, fmt.Errorf(`query edges "provisioned_hosts": %v`, err)
		}
		query.Where(provisionedhost.IDIn(edgeids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := edges[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected "provisioned_hosts" node returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.ProvisionedHosts = append(nodes[i].Edges.ProvisionedHosts, n)
			}
		}
	}

	return nodes, nil
}

func (pnq *ProvisionedNetworkQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := pnq.querySpec()
	return sqlgraph.CountNodes(ctx, pnq.driver, _spec)
}

func (pnq *ProvisionedNetworkQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := pnq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %v", err)
	}
	return n > 0, nil
}

func (pnq *ProvisionedNetworkQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   provisionednetwork.Table,
			Columns: provisionednetwork.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: provisionednetwork.FieldID,
			},
		},
		From:   pnq.sql,
		Unique: true,
	}
	if ps := pnq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := pnq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := pnq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := pnq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector, provisionednetwork.ValidColumn)
			}
		}
	}
	return _spec
}

func (pnq *ProvisionedNetworkQuery) sqlQuery() *sql.Selector {
	builder := sql.Dialect(pnq.driver.Dialect())
	t1 := builder.Table(provisionednetwork.Table)
	selector := builder.Select(t1.Columns(provisionednetwork.Columns...)...).From(t1)
	if pnq.sql != nil {
		selector = pnq.sql
		selector.Select(selector.Columns(provisionednetwork.Columns...)...)
	}
	for _, p := range pnq.predicates {
		p(selector)
	}
	for _, p := range pnq.order {
		p(selector, provisionednetwork.ValidColumn)
	}
	if offset := pnq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := pnq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ProvisionedNetworkGroupBy is the builder for group-by ProvisionedNetwork entities.
type ProvisionedNetworkGroupBy struct {
	config
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (pngb *ProvisionedNetworkGroupBy) Aggregate(fns ...AggregateFunc) *ProvisionedNetworkGroupBy {
	pngb.fns = append(pngb.fns, fns...)
	return pngb
}

// Scan applies the group-by query and scan the result into the given value.
func (pngb *ProvisionedNetworkGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := pngb.path(ctx)
	if err != nil {
		return err
	}
	pngb.sql = query
	return pngb.sqlScan(ctx, v)
}

// ScanX is like Scan, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) ScanX(ctx context.Context, v interface{}) {
	if err := pngb.Scan(ctx, v); err != nil {
		panic(err)
	}
}

// Strings returns list of strings from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Strings(ctx context.Context) ([]string, error) {
	if len(pngb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkGroupBy.Strings is not achievable when grouping more than 1 field")
	}
	var v []string
	if err := pngb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// StringsX is like Strings, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) StringsX(ctx context.Context) []string {
	v, err := pngb.Strings(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns a single string from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) String(ctx context.Context) (_ string, err error) {
	var v []string
	if v, err = pngb.Strings(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkGroupBy.Strings returned %d results when one was expected", len(v))
	}
	return
}

// StringX is like String, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) StringX(ctx context.Context) string {
	v, err := pngb.String(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Ints returns list of ints from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Ints(ctx context.Context) ([]int, error) {
	if len(pngb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkGroupBy.Ints is not achievable when grouping more than 1 field")
	}
	var v []int
	if err := pngb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// IntsX is like Ints, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) IntsX(ctx context.Context) []int {
	v, err := pngb.Ints(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Int returns a single int from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Int(ctx context.Context) (_ int, err error) {
	var v []int
	if v, err = pngb.Ints(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkGroupBy.Ints returned %d results when one was expected", len(v))
	}
	return
}

// IntX is like Int, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) IntX(ctx context.Context) int {
	v, err := pngb.Int(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64s returns list of float64s from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Float64s(ctx context.Context) ([]float64, error) {
	if len(pngb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkGroupBy.Float64s is not achievable when grouping more than 1 field")
	}
	var v []float64
	if err := pngb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Float64sX is like Float64s, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) Float64sX(ctx context.Context) []float64 {
	v, err := pngb.Float64s(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64 returns a single float64 from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Float64(ctx context.Context) (_ float64, err error) {
	var v []float64
	if v, err = pngb.Float64s(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkGroupBy.Float64s returned %d results when one was expected", len(v))
	}
	return
}

// Float64X is like Float64, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) Float64X(ctx context.Context) float64 {
	v, err := pngb.Float64(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bools returns list of bools from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Bools(ctx context.Context) ([]bool, error) {
	if len(pngb.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkGroupBy.Bools is not achievable when grouping more than 1 field")
	}
	var v []bool
	if err := pngb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// BoolsX is like Bools, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) BoolsX(ctx context.Context) []bool {
	v, err := pngb.Bools(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bool returns a single bool from group-by. It is only allowed when querying group-by with one field.
func (pngb *ProvisionedNetworkGroupBy) Bool(ctx context.Context) (_ bool, err error) {
	var v []bool
	if v, err = pngb.Bools(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkGroupBy.Bools returned %d results when one was expected", len(v))
	}
	return
}

// BoolX is like Bool, but panics if an error occurs.
func (pngb *ProvisionedNetworkGroupBy) BoolX(ctx context.Context) bool {
	v, err := pngb.Bool(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (pngb *ProvisionedNetworkGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range pngb.fields {
		if !provisionednetwork.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := pngb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := pngb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (pngb *ProvisionedNetworkGroupBy) sqlQuery() *sql.Selector {
	selector := pngb.sql
	columns := make([]string, 0, len(pngb.fields)+len(pngb.fns))
	columns = append(columns, pngb.fields...)
	for _, fn := range pngb.fns {
		columns = append(columns, fn(selector, provisionednetwork.ValidColumn))
	}
	return selector.Select(columns...).GroupBy(pngb.fields...)
}

// ProvisionedNetworkSelect is the builder for select fields of ProvisionedNetwork entities.
type ProvisionedNetworkSelect struct {
	config
	fields []string
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Scan applies the selector query and scan the result into the given value.
func (pns *ProvisionedNetworkSelect) Scan(ctx context.Context, v interface{}) error {
	query, err := pns.path(ctx)
	if err != nil {
		return err
	}
	pns.sql = query
	return pns.sqlScan(ctx, v)
}

// ScanX is like Scan, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) ScanX(ctx context.Context, v interface{}) {
	if err := pns.Scan(ctx, v); err != nil {
		panic(err)
	}
}

// Strings returns list of strings from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Strings(ctx context.Context) ([]string, error) {
	if len(pns.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkSelect.Strings is not achievable when selecting more than 1 field")
	}
	var v []string
	if err := pns.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// StringsX is like Strings, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) StringsX(ctx context.Context) []string {
	v, err := pns.Strings(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns a single string from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) String(ctx context.Context) (_ string, err error) {
	var v []string
	if v, err = pns.Strings(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkSelect.Strings returned %d results when one was expected", len(v))
	}
	return
}

// StringX is like String, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) StringX(ctx context.Context) string {
	v, err := pns.String(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Ints returns list of ints from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Ints(ctx context.Context) ([]int, error) {
	if len(pns.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkSelect.Ints is not achievable when selecting more than 1 field")
	}
	var v []int
	if err := pns.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// IntsX is like Ints, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) IntsX(ctx context.Context) []int {
	v, err := pns.Ints(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Int returns a single int from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Int(ctx context.Context) (_ int, err error) {
	var v []int
	if v, err = pns.Ints(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkSelect.Ints returned %d results when one was expected", len(v))
	}
	return
}

// IntX is like Int, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) IntX(ctx context.Context) int {
	v, err := pns.Int(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64s returns list of float64s from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Float64s(ctx context.Context) ([]float64, error) {
	if len(pns.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkSelect.Float64s is not achievable when selecting more than 1 field")
	}
	var v []float64
	if err := pns.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Float64sX is like Float64s, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) Float64sX(ctx context.Context) []float64 {
	v, err := pns.Float64s(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64 returns a single float64 from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Float64(ctx context.Context) (_ float64, err error) {
	var v []float64
	if v, err = pns.Float64s(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkSelect.Float64s returned %d results when one was expected", len(v))
	}
	return
}

// Float64X is like Float64, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) Float64X(ctx context.Context) float64 {
	v, err := pns.Float64(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bools returns list of bools from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Bools(ctx context.Context) ([]bool, error) {
	if len(pns.fields) > 1 {
		return nil, errors.New("ent: ProvisionedNetworkSelect.Bools is not achievable when selecting more than 1 field")
	}
	var v []bool
	if err := pns.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// BoolsX is like Bools, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) BoolsX(ctx context.Context) []bool {
	v, err := pns.Bools(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bool returns a single bool from selector. It is only allowed when selecting one field.
func (pns *ProvisionedNetworkSelect) Bool(ctx context.Context) (_ bool, err error) {
	var v []bool
	if v, err = pns.Bools(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{provisionednetwork.Label}
	default:
		err = fmt.Errorf("ent: ProvisionedNetworkSelect.Bools returned %d results when one was expected", len(v))
	}
	return
}

// BoolX is like Bool, but panics if an error occurs.
func (pns *ProvisionedNetworkSelect) BoolX(ctx context.Context) bool {
	v, err := pns.Bool(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (pns *ProvisionedNetworkSelect) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range pns.fields {
		if !provisionednetwork.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for selection", f)}
		}
	}
	rows := &sql.Rows{}
	query, args := pns.sqlQuery().Query()
	if err := pns.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (pns *ProvisionedNetworkSelect) sqlQuery() sql.Querier {
	selector := pns.sql
	selector.Select(selector.Columns(pns.fields...)...)
	return selector
}
