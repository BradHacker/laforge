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
	"github.com/gen0cide/laforge/ent/disk"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/hostdependency"
	"github.com/gen0cide/laforge/ent/includednetwork"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/gen0cide/laforge/ent/user"
	"github.com/google/uuid"
)

// HostQuery is the builder for querying Host entities.
type HostQuery struct {
	config
	limit                        *int
	offset                       *int
	unique                       *bool
	order                        []OrderFunc
	fields                       []string
	predicates                   []predicate.Host
	withDisk                     *DiskQuery
	withUsers                    *UserQuery
	withEnvironment              *EnvironmentQuery
	withIncludedNetworks         *IncludedNetworkQuery
	withDependOnHostDependency   *HostDependencyQuery
	withRequiredByHostDependency *HostDependencyQuery
	withFKs                      bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the HostQuery builder.
func (hq *HostQuery) Where(ps ...predicate.Host) *HostQuery {
	hq.predicates = append(hq.predicates, ps...)
	return hq
}

// Limit adds a limit step to the query.
func (hq *HostQuery) Limit(limit int) *HostQuery {
	hq.limit = &limit
	return hq
}

// Offset adds an offset step to the query.
func (hq *HostQuery) Offset(offset int) *HostQuery {
	hq.offset = &offset
	return hq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (hq *HostQuery) Unique(unique bool) *HostQuery {
	hq.unique = &unique
	return hq
}

// Order adds an order step to the query.
func (hq *HostQuery) Order(o ...OrderFunc) *HostQuery {
	hq.order = append(hq.order, o...)
	return hq
}

// QueryDisk chains the current query on the "Disk" edge.
func (hq *HostQuery) QueryDisk() *DiskQuery {
	query := &DiskQuery{config: hq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(host.Table, host.FieldID, selector),
			sqlgraph.To(disk.Table, disk.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, host.DiskTable, host.DiskColumn),
		)
		fromU = sqlgraph.SetNeighbors(hq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryUsers chains the current query on the "Users" edge.
func (hq *HostQuery) QueryUsers() *UserQuery {
	query := &UserQuery{config: hq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(host.Table, host.FieldID, selector),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, host.UsersTable, host.UsersColumn),
		)
		fromU = sqlgraph.SetNeighbors(hq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryEnvironment chains the current query on the "Environment" edge.
func (hq *HostQuery) QueryEnvironment() *EnvironmentQuery {
	query := &EnvironmentQuery{config: hq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(host.Table, host.FieldID, selector),
			sqlgraph.To(environment.Table, environment.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, host.EnvironmentTable, host.EnvironmentColumn),
		)
		fromU = sqlgraph.SetNeighbors(hq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryIncludedNetworks chains the current query on the "IncludedNetworks" edge.
func (hq *HostQuery) QueryIncludedNetworks() *IncludedNetworkQuery {
	query := &IncludedNetworkQuery{config: hq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(host.Table, host.FieldID, selector),
			sqlgraph.To(includednetwork.Table, includednetwork.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, host.IncludedNetworksTable, host.IncludedNetworksPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(hq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryDependOnHostDependency chains the current query on the "DependOnHostDependency" edge.
func (hq *HostQuery) QueryDependOnHostDependency() *HostDependencyQuery {
	query := &HostDependencyQuery{config: hq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(host.Table, host.FieldID, selector),
			sqlgraph.To(hostdependency.Table, hostdependency.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, host.DependOnHostDependencyTable, host.DependOnHostDependencyColumn),
		)
		fromU = sqlgraph.SetNeighbors(hq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryRequiredByHostDependency chains the current query on the "RequiredByHostDependency" edge.
func (hq *HostQuery) QueryRequiredByHostDependency() *HostDependencyQuery {
	query := &HostDependencyQuery{config: hq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := hq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(host.Table, host.FieldID, selector),
			sqlgraph.To(hostdependency.Table, hostdependency.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, host.RequiredByHostDependencyTable, host.RequiredByHostDependencyColumn),
		)
		fromU = sqlgraph.SetNeighbors(hq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first Host entity from the query.
// Returns a *NotFoundError when no Host was found.
func (hq *HostQuery) First(ctx context.Context) (*Host, error) {
	nodes, err := hq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{host.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (hq *HostQuery) FirstX(ctx context.Context) *Host {
	node, err := hq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Host ID from the query.
// Returns a *NotFoundError when no Host ID was found.
func (hq *HostQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = hq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{host.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (hq *HostQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := hq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Host entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Host entity is found.
// Returns a *NotFoundError when no Host entities are found.
func (hq *HostQuery) Only(ctx context.Context) (*Host, error) {
	nodes, err := hq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{host.Label}
	default:
		return nil, &NotSingularError{host.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (hq *HostQuery) OnlyX(ctx context.Context) *Host {
	node, err := hq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Host ID in the query.
// Returns a *NotSingularError when more than one Host ID is found.
// Returns a *NotFoundError when no entities are found.
func (hq *HostQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = hq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{host.Label}
	default:
		err = &NotSingularError{host.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (hq *HostQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := hq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Hosts.
func (hq *HostQuery) All(ctx context.Context) ([]*Host, error) {
	if err := hq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return hq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (hq *HostQuery) AllX(ctx context.Context) []*Host {
	nodes, err := hq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Host IDs.
func (hq *HostQuery) IDs(ctx context.Context) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	if err := hq.Select(host.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (hq *HostQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := hq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (hq *HostQuery) Count(ctx context.Context) (int, error) {
	if err := hq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return hq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (hq *HostQuery) CountX(ctx context.Context) int {
	count, err := hq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (hq *HostQuery) Exist(ctx context.Context) (bool, error) {
	if err := hq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return hq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (hq *HostQuery) ExistX(ctx context.Context) bool {
	exist, err := hq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the HostQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (hq *HostQuery) Clone() *HostQuery {
	if hq == nil {
		return nil
	}
	return &HostQuery{
		config:                       hq.config,
		limit:                        hq.limit,
		offset:                       hq.offset,
		order:                        append([]OrderFunc{}, hq.order...),
		predicates:                   append([]predicate.Host{}, hq.predicates...),
		withDisk:                     hq.withDisk.Clone(),
		withUsers:                    hq.withUsers.Clone(),
		withEnvironment:              hq.withEnvironment.Clone(),
		withIncludedNetworks:         hq.withIncludedNetworks.Clone(),
		withDependOnHostDependency:   hq.withDependOnHostDependency.Clone(),
		withRequiredByHostDependency: hq.withRequiredByHostDependency.Clone(),
		// clone intermediate query.
		sql:    hq.sql.Clone(),
		path:   hq.path,
		unique: hq.unique,
	}
}

// WithDisk tells the query-builder to eager-load the nodes that are connected to
// the "Disk" edge. The optional arguments are used to configure the query builder of the edge.
func (hq *HostQuery) WithDisk(opts ...func(*DiskQuery)) *HostQuery {
	query := &DiskQuery{config: hq.config}
	for _, opt := range opts {
		opt(query)
	}
	hq.withDisk = query
	return hq
}

// WithUsers tells the query-builder to eager-load the nodes that are connected to
// the "Users" edge. The optional arguments are used to configure the query builder of the edge.
func (hq *HostQuery) WithUsers(opts ...func(*UserQuery)) *HostQuery {
	query := &UserQuery{config: hq.config}
	for _, opt := range opts {
		opt(query)
	}
	hq.withUsers = query
	return hq
}

// WithEnvironment tells the query-builder to eager-load the nodes that are connected to
// the "Environment" edge. The optional arguments are used to configure the query builder of the edge.
func (hq *HostQuery) WithEnvironment(opts ...func(*EnvironmentQuery)) *HostQuery {
	query := &EnvironmentQuery{config: hq.config}
	for _, opt := range opts {
		opt(query)
	}
	hq.withEnvironment = query
	return hq
}

// WithIncludedNetworks tells the query-builder to eager-load the nodes that are connected to
// the "IncludedNetworks" edge. The optional arguments are used to configure the query builder of the edge.
func (hq *HostQuery) WithIncludedNetworks(opts ...func(*IncludedNetworkQuery)) *HostQuery {
	query := &IncludedNetworkQuery{config: hq.config}
	for _, opt := range opts {
		opt(query)
	}
	hq.withIncludedNetworks = query
	return hq
}

// WithDependOnHostDependency tells the query-builder to eager-load the nodes that are connected to
// the "DependOnHostDependency" edge. The optional arguments are used to configure the query builder of the edge.
func (hq *HostQuery) WithDependOnHostDependency(opts ...func(*HostDependencyQuery)) *HostQuery {
	query := &HostDependencyQuery{config: hq.config}
	for _, opt := range opts {
		opt(query)
	}
	hq.withDependOnHostDependency = query
	return hq
}

// WithRequiredByHostDependency tells the query-builder to eager-load the nodes that are connected to
// the "RequiredByHostDependency" edge. The optional arguments are used to configure the query builder of the edge.
func (hq *HostQuery) WithRequiredByHostDependency(opts ...func(*HostDependencyQuery)) *HostQuery {
	query := &HostDependencyQuery{config: hq.config}
	for _, opt := range opts {
		opt(query)
	}
	hq.withRequiredByHostDependency = query
	return hq
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
//	client.Host.Query().
//		GroupBy(host.FieldHclID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (hq *HostQuery) GroupBy(field string, fields ...string) *HostGroupBy {
	grbuild := &HostGroupBy{config: hq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := hq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return hq.sqlQuery(ctx), nil
	}
	grbuild.label = host.Label
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
//	client.Host.Query().
//		Select(host.FieldHclID).
//		Scan(ctx, &v)
func (hq *HostQuery) Select(fields ...string) *HostSelect {
	hq.fields = append(hq.fields, fields...)
	selbuild := &HostSelect{HostQuery: hq}
	selbuild.label = host.Label
	selbuild.flds, selbuild.scan = &hq.fields, selbuild.Scan
	return selbuild
}

func (hq *HostQuery) prepareQuery(ctx context.Context) error {
	for _, f := range hq.fields {
		if !host.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if hq.path != nil {
		prev, err := hq.path(ctx)
		if err != nil {
			return err
		}
		hq.sql = prev
	}
	return nil
}

func (hq *HostQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Host, error) {
	var (
		nodes       = []*Host{}
		withFKs     = hq.withFKs
		_spec       = hq.querySpec()
		loadedTypes = [6]bool{
			hq.withDisk != nil,
			hq.withUsers != nil,
			hq.withEnvironment != nil,
			hq.withIncludedNetworks != nil,
			hq.withDependOnHostDependency != nil,
			hq.withRequiredByHostDependency != nil,
		}
	)
	if hq.withEnvironment != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, host.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*Host).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &Host{config: hq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, hq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := hq.withDisk; query != nil {
		if err := hq.loadDisk(ctx, query, nodes, nil,
			func(n *Host, e *Disk) { n.Edges.Disk = e }); err != nil {
			return nil, err
		}
	}
	if query := hq.withUsers; query != nil {
		if err := hq.loadUsers(ctx, query, nodes,
			func(n *Host) { n.Edges.Users = []*User{} },
			func(n *Host, e *User) { n.Edges.Users = append(n.Edges.Users, e) }); err != nil {
			return nil, err
		}
	}
	if query := hq.withEnvironment; query != nil {
		if err := hq.loadEnvironment(ctx, query, nodes, nil,
			func(n *Host, e *Environment) { n.Edges.Environment = e }); err != nil {
			return nil, err
		}
	}
	if query := hq.withIncludedNetworks; query != nil {
		if err := hq.loadIncludedNetworks(ctx, query, nodes,
			func(n *Host) { n.Edges.IncludedNetworks = []*IncludedNetwork{} },
			func(n *Host, e *IncludedNetwork) { n.Edges.IncludedNetworks = append(n.Edges.IncludedNetworks, e) }); err != nil {
			return nil, err
		}
	}
	if query := hq.withDependOnHostDependency; query != nil {
		if err := hq.loadDependOnHostDependency(ctx, query, nodes,
			func(n *Host) { n.Edges.DependOnHostDependency = []*HostDependency{} },
			func(n *Host, e *HostDependency) {
				n.Edges.DependOnHostDependency = append(n.Edges.DependOnHostDependency, e)
			}); err != nil {
			return nil, err
		}
	}
	if query := hq.withRequiredByHostDependency; query != nil {
		if err := hq.loadRequiredByHostDependency(ctx, query, nodes,
			func(n *Host) { n.Edges.RequiredByHostDependency = []*HostDependency{} },
			func(n *Host, e *HostDependency) {
				n.Edges.RequiredByHostDependency = append(n.Edges.RequiredByHostDependency, e)
			}); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (hq *HostQuery) loadDisk(ctx context.Context, query *DiskQuery, nodes []*Host, init func(*Host), assign func(*Host, *Disk)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Host)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
	}
	query.withFKs = true
	query.Where(predicate.Disk(func(s *sql.Selector) {
		s.Where(sql.InValues(host.DiskColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.host_disk
		if fk == nil {
			return fmt.Errorf(`foreign-key "host_disk" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "host_disk" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (hq *HostQuery) loadUsers(ctx context.Context, query *UserQuery, nodes []*Host, init func(*Host), assign func(*Host, *User)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Host)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.User(func(s *sql.Selector) {
		s.Where(sql.InValues(host.UsersColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.host_users
		if fk == nil {
			return fmt.Errorf(`foreign-key "host_users" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "host_users" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (hq *HostQuery) loadEnvironment(ctx context.Context, query *EnvironmentQuery, nodes []*Host, init func(*Host), assign func(*Host, *Environment)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*Host)
	for i := range nodes {
		if nodes[i].environment_hosts == nil {
			continue
		}
		fk := *nodes[i].environment_hosts
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
			return fmt.Errorf(`unexpected foreign-key "environment_hosts" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}
func (hq *HostQuery) loadIncludedNetworks(ctx context.Context, query *IncludedNetworkQuery, nodes []*Host, init func(*Host), assign func(*Host, *IncludedNetwork)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[uuid.UUID]*Host)
	nids := make(map[uuid.UUID]map[*Host]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(host.IncludedNetworksTable)
		s.Join(joinT).On(s.C(includednetwork.FieldID), joinT.C(host.IncludedNetworksPrimaryKey[0]))
		s.Where(sql.InValues(joinT.C(host.IncludedNetworksPrimaryKey[1]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(host.IncludedNetworksPrimaryKey[1]))
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
				nids[inValue] = map[*Host]struct{}{byID[outValue]: struct{}{}}
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
			return fmt.Errorf(`unexpected "IncludedNetworks" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}
func (hq *HostQuery) loadDependOnHostDependency(ctx context.Context, query *HostDependencyQuery, nodes []*Host, init func(*Host), assign func(*Host, *HostDependency)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Host)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.HostDependency(func(s *sql.Selector) {
		s.Where(sql.InValues(host.DependOnHostDependencyColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.host_dependency_depend_on
		if fk == nil {
			return fmt.Errorf(`foreign-key "host_dependency_depend_on" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "host_dependency_depend_on" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}
func (hq *HostQuery) loadRequiredByHostDependency(ctx context.Context, query *HostDependencyQuery, nodes []*Host, init func(*Host), assign func(*Host, *HostDependency)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[uuid.UUID]*Host)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	query.withFKs = true
	query.Where(predicate.HostDependency(func(s *sql.Selector) {
		s.Where(sql.InValues(host.RequiredByHostDependencyColumn, fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.host_dependency_required_by
		if fk == nil {
			return fmt.Errorf(`foreign-key "host_dependency_required_by" is nil for node %v`, n.ID)
		}
		node, ok := nodeids[*fk]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "host_dependency_required_by" returned %v for node %v`, *fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (hq *HostQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := hq.querySpec()
	_spec.Node.Columns = hq.fields
	if len(hq.fields) > 0 {
		_spec.Unique = hq.unique != nil && *hq.unique
	}
	return sqlgraph.CountNodes(ctx, hq.driver, _spec)
}

func (hq *HostQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := hq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (hq *HostQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   host.Table,
			Columns: host.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeUUID,
				Column: host.FieldID,
			},
		},
		From:   hq.sql,
		Unique: true,
	}
	if unique := hq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := hq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, host.FieldID)
		for i := range fields {
			if fields[i] != host.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := hq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := hq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := hq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := hq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (hq *HostQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(hq.driver.Dialect())
	t1 := builder.Table(host.Table)
	columns := hq.fields
	if len(columns) == 0 {
		columns = host.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if hq.sql != nil {
		selector = hq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if hq.unique != nil && *hq.unique {
		selector.Distinct()
	}
	for _, p := range hq.predicates {
		p(selector)
	}
	for _, p := range hq.order {
		p(selector)
	}
	if offset := hq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := hq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// HostGroupBy is the group-by builder for Host entities.
type HostGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (hgb *HostGroupBy) Aggregate(fns ...AggregateFunc) *HostGroupBy {
	hgb.fns = append(hgb.fns, fns...)
	return hgb
}

// Scan applies the group-by query and scans the result into the given value.
func (hgb *HostGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := hgb.path(ctx)
	if err != nil {
		return err
	}
	hgb.sql = query
	return hgb.sqlScan(ctx, v)
}

func (hgb *HostGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range hgb.fields {
		if !host.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := hgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := hgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (hgb *HostGroupBy) sqlQuery() *sql.Selector {
	selector := hgb.sql.Select()
	aggregation := make([]string, 0, len(hgb.fns))
	for _, fn := range hgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(hgb.fields)+len(hgb.fns))
		for _, f := range hgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(hgb.fields...)...)
}

// HostSelect is the builder for selecting fields of Host entities.
type HostSelect struct {
	*HostQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (hs *HostSelect) Scan(ctx context.Context, v interface{}) error {
	if err := hs.prepareQuery(ctx); err != nil {
		return err
	}
	hs.sql = hs.HostQuery.sqlQuery(ctx)
	return hs.sqlScan(ctx, v)
}

func (hs *HostSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := hs.sql.Query()
	if err := hs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
