// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/hostdependency"
	"github.com/gen0cide/laforge/ent/network"
	"github.com/google/uuid"
)

// HostDependency is the model entity for the HostDependency schema.
type HostDependency struct {
	config ` json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// HostID holds the value of the "host_id" field.
	HostID string `json:"host_id,omitempty" hcl:"host,attr"`
	// NetworkID holds the value of the "network_id" field.
	NetworkID string `json:"network_id,omitempty" hcl:"network,attr"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the HostDependencyQuery when eager-loading is set.
	Edges HostDependencyEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// RequiredBy holds the value of the RequiredBy edge.
	HCLRequiredBy *Host `json:"RequiredBy,omitempty"`
	// DependOnHost holds the value of the DependOnHost edge.
	HCLDependOnHost *Host `json:"DependOnHost,omitempty"`
	// DependOnNetwork holds the value of the DependOnNetwork edge.
	HCLDependOnNetwork *Network `json:"DependOnNetwork,omitempty"`
	// Environment holds the value of the Environment edge.
	HCLEnvironment *Environment `json:"Environment,omitempty"`
	//
	environment_host_dependencies     *uuid.UUID
	host_dependency_required_by       *uuid.UUID
	host_dependency_depend_on_host    *uuid.UUID
	host_dependency_depend_on_network *uuid.UUID
}

// HostDependencyEdges holds the relations/edges for other nodes in the graph.
type HostDependencyEdges struct {
	// RequiredBy holds the value of the RequiredBy edge.
	RequiredBy *Host `json:"RequiredBy,omitempty"`
	// DependOnHost holds the value of the DependOnHost edge.
	DependOnHost *Host `json:"DependOnHost,omitempty"`
	// DependOnNetwork holds the value of the DependOnNetwork edge.
	DependOnNetwork *Network `json:"DependOnNetwork,omitempty"`
	// Environment holds the value of the Environment edge.
	Environment *Environment `json:"Environment,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
}

// RequiredByOrErr returns the RequiredBy value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e HostDependencyEdges) RequiredByOrErr() (*Host, error) {
	if e.loadedTypes[0] {
		if e.RequiredBy == nil {
			// The edge RequiredBy was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: host.Label}
		}
		return e.RequiredBy, nil
	}
	return nil, &NotLoadedError{edge: "RequiredBy"}
}

// DependOnHostOrErr returns the DependOnHost value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e HostDependencyEdges) DependOnHostOrErr() (*Host, error) {
	if e.loadedTypes[1] {
		if e.DependOnHost == nil {
			// The edge DependOnHost was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: host.Label}
		}
		return e.DependOnHost, nil
	}
	return nil, &NotLoadedError{edge: "DependOnHost"}
}

// DependOnNetworkOrErr returns the DependOnNetwork value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e HostDependencyEdges) DependOnNetworkOrErr() (*Network, error) {
	if e.loadedTypes[2] {
		if e.DependOnNetwork == nil {
			// The edge DependOnNetwork was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: network.Label}
		}
		return e.DependOnNetwork, nil
	}
	return nil, &NotLoadedError{edge: "DependOnNetwork"}
}

// EnvironmentOrErr returns the Environment value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e HostDependencyEdges) EnvironmentOrErr() (*Environment, error) {
	if e.loadedTypes[3] {
		if e.Environment == nil {
			// The edge Environment was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: environment.Label}
		}
		return e.Environment, nil
	}
	return nil, &NotLoadedError{edge: "Environment"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*HostDependency) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case hostdependency.FieldHostID, hostdependency.FieldNetworkID:
			values[i] = new(sql.NullString)
		case hostdependency.FieldID:
			values[i] = new(uuid.UUID)
		case hostdependency.ForeignKeys[0]: // environment_host_dependencies
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case hostdependency.ForeignKeys[1]: // host_dependency_required_by
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case hostdependency.ForeignKeys[2]: // host_dependency_depend_on_host
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case hostdependency.ForeignKeys[3]: // host_dependency_depend_on_network
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type HostDependency", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the HostDependency fields.
func (hd *HostDependency) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case hostdependency.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				hd.ID = *value
			}
		case hostdependency.FieldHostID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field host_id", values[i])
			} else if value.Valid {
				hd.HostID = value.String
			}
		case hostdependency.FieldNetworkID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field network_id", values[i])
			} else if value.Valid {
				hd.NetworkID = value.String
			}
		case hostdependency.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field environment_host_dependencies", values[i])
			} else if value.Valid {
				hd.environment_host_dependencies = new(uuid.UUID)
				*hd.environment_host_dependencies = *value.S.(*uuid.UUID)
			}
		case hostdependency.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field host_dependency_required_by", values[i])
			} else if value.Valid {
				hd.host_dependency_required_by = new(uuid.UUID)
				*hd.host_dependency_required_by = *value.S.(*uuid.UUID)
			}
		case hostdependency.ForeignKeys[2]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field host_dependency_depend_on_host", values[i])
			} else if value.Valid {
				hd.host_dependency_depend_on_host = new(uuid.UUID)
				*hd.host_dependency_depend_on_host = *value.S.(*uuid.UUID)
			}
		case hostdependency.ForeignKeys[3]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field host_dependency_depend_on_network", values[i])
			} else if value.Valid {
				hd.host_dependency_depend_on_network = new(uuid.UUID)
				*hd.host_dependency_depend_on_network = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryRequiredBy queries the "RequiredBy" edge of the HostDependency entity.
func (hd *HostDependency) QueryRequiredBy() *HostQuery {
	return (&HostDependencyClient{config: hd.config}).QueryRequiredBy(hd)
}

// QueryDependOnHost queries the "DependOnHost" edge of the HostDependency entity.
func (hd *HostDependency) QueryDependOnHost() *HostQuery {
	return (&HostDependencyClient{config: hd.config}).QueryDependOnHost(hd)
}

// QueryDependOnNetwork queries the "DependOnNetwork" edge of the HostDependency entity.
func (hd *HostDependency) QueryDependOnNetwork() *NetworkQuery {
	return (&HostDependencyClient{config: hd.config}).QueryDependOnNetwork(hd)
}

// QueryEnvironment queries the "Environment" edge of the HostDependency entity.
func (hd *HostDependency) QueryEnvironment() *EnvironmentQuery {
	return (&HostDependencyClient{config: hd.config}).QueryEnvironment(hd)
}

// Update returns a builder for updating this HostDependency.
// Note that you need to call HostDependency.Unwrap() before calling this method if this HostDependency
// was returned from a transaction, and the transaction was committed or rolled back.
func (hd *HostDependency) Update() *HostDependencyUpdateOne {
	return (&HostDependencyClient{config: hd.config}).UpdateOne(hd)
}

// Unwrap unwraps the HostDependency entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (hd *HostDependency) Unwrap() *HostDependency {
	tx, ok := hd.config.driver.(*txDriver)
	if !ok {
		panic("ent: HostDependency is not a transactional entity")
	}
	hd.config.driver = tx.drv
	return hd
}

// String implements the fmt.Stringer.
func (hd *HostDependency) String() string {
	var builder strings.Builder
	builder.WriteString("HostDependency(")
	builder.WriteString(fmt.Sprintf("id=%v", hd.ID))
	builder.WriteString(", host_id=")
	builder.WriteString(hd.HostID)
	builder.WriteString(", network_id=")
	builder.WriteString(hd.NetworkID)
	builder.WriteByte(')')
	return builder.String()
}

// HostDependencies is a parsable slice of HostDependency.
type HostDependencies []*HostDependency

func (hd HostDependencies) config(cfg config) {
	for _i := range hd {
		hd[_i].config = cfg
	}
}
