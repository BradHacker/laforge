// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/network"
	"github.com/google/uuid"
)

// Network is the model entity for the Network schema.
type Network struct {
	config ` json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// HCLID holds the value of the "hcl_id" field.
	HCLID string `json:"hcl_id,omitempty" hcl:"id,label"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty" hcl:"name,attr"`
	// Cidr holds the value of the "cidr" field.
	Cidr string `json:"cidr,omitempty" hcl:"cidr,attr"`
	// VdiVisible holds the value of the "vdi_visible" field.
	VdiVisible bool `json:"vdi_visible,omitempty" hcl:"vdi_visible,optional"`
	// Vars holds the value of the "vars" field.
	Vars map[string]string `json:"vars,omitempty" hcl:"vars,optional"`
	// Tags holds the value of the "tags" field.
	Tags map[string]string `json:"tags,omitempty" hcl:"tags,optional"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the NetworkQuery when eager-loading is set.
	Edges NetworkEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// Environment holds the value of the Environment edge.
	HCLEnvironment *Environment `json:"Environment,omitempty"`
	// HostDependencies holds the value of the HostDependencies edge.
	HCLHostDependencies []*HostDependency `json:"HostDependencies,omitempty"`
	// IncludedNetworks holds the value of the IncludedNetworks edge.
	HCLIncludedNetworks  []*IncludedNetwork `json:"IncludedNetworks,omitempty"`
	environment_networks *uuid.UUID
	selectValues         sql.SelectValues
}

// NetworkEdges holds the relations/edges for other nodes in the graph.
type NetworkEdges struct {
	// Environment holds the value of the Environment edge.
	Environment *Environment `json:"Environment,omitempty"`
	// HostDependencies holds the value of the HostDependencies edge.
	HostDependencies []*HostDependency `json:"HostDependencies,omitempty"`
	// IncludedNetworks holds the value of the IncludedNetworks edge.
	IncludedNetworks []*IncludedNetwork `json:"IncludedNetworks,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [3]bool
	// totalCount holds the count of the edges above.
	totalCount [3]map[string]int

	namedHostDependencies map[string][]*HostDependency
	namedIncludedNetworks map[string][]*IncludedNetwork
}

// EnvironmentOrErr returns the Environment value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e NetworkEdges) EnvironmentOrErr() (*Environment, error) {
	if e.loadedTypes[0] {
		if e.Environment == nil {
			// Edge was loaded but was not found.
			return nil, &NotFoundError{label: environment.Label}
		}
		return e.Environment, nil
	}
	return nil, &NotLoadedError{edge: "Environment"}
}

// HostDependenciesOrErr returns the HostDependencies value or an error if the edge
// was not loaded in eager-loading.
func (e NetworkEdges) HostDependenciesOrErr() ([]*HostDependency, error) {
	if e.loadedTypes[1] {
		return e.HostDependencies, nil
	}
	return nil, &NotLoadedError{edge: "HostDependencies"}
}

// IncludedNetworksOrErr returns the IncludedNetworks value or an error if the edge
// was not loaded in eager-loading.
func (e NetworkEdges) IncludedNetworksOrErr() ([]*IncludedNetwork, error) {
	if e.loadedTypes[2] {
		return e.IncludedNetworks, nil
	}
	return nil, &NotLoadedError{edge: "IncludedNetworks"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Network) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case network.FieldVars, network.FieldTags:
			values[i] = new([]byte)
		case network.FieldVdiVisible:
			values[i] = new(sql.NullBool)
		case network.FieldHCLID, network.FieldName, network.FieldCidr:
			values[i] = new(sql.NullString)
		case network.FieldID:
			values[i] = new(uuid.UUID)
		case network.ForeignKeys[0]: // environment_networks
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Network fields.
func (n *Network) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case network.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				n.ID = *value
			}
		case network.FieldHCLID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field hcl_id", values[i])
			} else if value.Valid {
				n.HCLID = value.String
			}
		case network.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				n.Name = value.String
			}
		case network.FieldCidr:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field cidr", values[i])
			} else if value.Valid {
				n.Cidr = value.String
			}
		case network.FieldVdiVisible:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field vdi_visible", values[i])
			} else if value.Valid {
				n.VdiVisible = value.Bool
			}
		case network.FieldVars:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field vars", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &n.Vars); err != nil {
					return fmt.Errorf("unmarshal field vars: %w", err)
				}
			}
		case network.FieldTags:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field tags", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &n.Tags); err != nil {
					return fmt.Errorf("unmarshal field tags: %w", err)
				}
			}
		case network.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field environment_networks", values[i])
			} else if value.Valid {
				n.environment_networks = new(uuid.UUID)
				*n.environment_networks = *value.S.(*uuid.UUID)
			}
		default:
			n.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Network.
// This includes values selected through modifiers, order, etc.
func (n *Network) Value(name string) (ent.Value, error) {
	return n.selectValues.Get(name)
}

// QueryEnvironment queries the "Environment" edge of the Network entity.
func (n *Network) QueryEnvironment() *EnvironmentQuery {
	return NewNetworkClient(n.config).QueryEnvironment(n)
}

// QueryHostDependencies queries the "HostDependencies" edge of the Network entity.
func (n *Network) QueryHostDependencies() *HostDependencyQuery {
	return NewNetworkClient(n.config).QueryHostDependencies(n)
}

// QueryIncludedNetworks queries the "IncludedNetworks" edge of the Network entity.
func (n *Network) QueryIncludedNetworks() *IncludedNetworkQuery {
	return NewNetworkClient(n.config).QueryIncludedNetworks(n)
}

// Update returns a builder for updating this Network.
// Note that you need to call Network.Unwrap() before calling this method if this Network
// was returned from a transaction, and the transaction was committed or rolled back.
func (n *Network) Update() *NetworkUpdateOne {
	return NewNetworkClient(n.config).UpdateOne(n)
}

// Unwrap unwraps the Network entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (n *Network) Unwrap() *Network {
	_tx, ok := n.config.driver.(*txDriver)
	if !ok {
		panic("ent: Network is not a transactional entity")
	}
	n.config.driver = _tx.drv
	return n
}

// String implements the fmt.Stringer.
func (n *Network) String() string {
	var builder strings.Builder
	builder.WriteString("Network(")
	builder.WriteString(fmt.Sprintf("id=%v, ", n.ID))
	builder.WriteString("hcl_id=")
	builder.WriteString(n.HCLID)
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(n.Name)
	builder.WriteString(", ")
	builder.WriteString("cidr=")
	builder.WriteString(n.Cidr)
	builder.WriteString(", ")
	builder.WriteString("vdi_visible=")
	builder.WriteString(fmt.Sprintf("%v", n.VdiVisible))
	builder.WriteString(", ")
	builder.WriteString("vars=")
	builder.WriteString(fmt.Sprintf("%v", n.Vars))
	builder.WriteString(", ")
	builder.WriteString("tags=")
	builder.WriteString(fmt.Sprintf("%v", n.Tags))
	builder.WriteByte(')')
	return builder.String()
}

// NamedHostDependencies returns the HostDependencies named value or an error if the edge was not
// loaded in eager-loading with this name.
func (n *Network) NamedHostDependencies(name string) ([]*HostDependency, error) {
	if n.Edges.namedHostDependencies == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := n.Edges.namedHostDependencies[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (n *Network) appendNamedHostDependencies(name string, edges ...*HostDependency) {
	if n.Edges.namedHostDependencies == nil {
		n.Edges.namedHostDependencies = make(map[string][]*HostDependency)
	}
	if len(edges) == 0 {
		n.Edges.namedHostDependencies[name] = []*HostDependency{}
	} else {
		n.Edges.namedHostDependencies[name] = append(n.Edges.namedHostDependencies[name], edges...)
	}
}

// NamedIncludedNetworks returns the IncludedNetworks named value or an error if the edge was not
// loaded in eager-loading with this name.
func (n *Network) NamedIncludedNetworks(name string) ([]*IncludedNetwork, error) {
	if n.Edges.namedIncludedNetworks == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := n.Edges.namedIncludedNetworks[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (n *Network) appendNamedIncludedNetworks(name string, edges ...*IncludedNetwork) {
	if n.Edges.namedIncludedNetworks == nil {
		n.Edges.namedIncludedNetworks = make(map[string][]*IncludedNetwork)
	}
	if len(edges) == 0 {
		n.Edges.namedIncludedNetworks[name] = []*IncludedNetwork{}
	} else {
		n.Edges.namedIncludedNetworks[name] = append(n.Edges.namedIncludedNetworks[name], edges...)
	}
}

// Networks is a parsable slice of Network.
type Networks []*Network
