// Code generated by entc, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"github.com/facebook/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/agentstatus"
)

// AgentStatus is the model entity for the AgentStatus schema.
type AgentStatus struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// ClientID holds the value of the "ClientID" field.
	ClientID string `json:"ClientID,omitempty"`
	// Hostname holds the value of the "Hostname" field.
	Hostname string `json:"Hostname,omitempty"`
	// UpTime holds the value of the "UpTime" field.
	UpTime int64 `json:"UpTime,omitempty"`
	// BootTime holds the value of the "BootTime" field.
	BootTime int64 `json:"BootTime,omitempty"`
	// NumProcs holds the value of the "NumProcs" field.
	NumProcs int64 `json:"NumProcs,omitempty"`
	// Os holds the value of the "Os" field.
	Os string `json:"Os,omitempty"`
	// HostID holds the value of the "HostID" field.
	HostID string `json:"HostID,omitempty"`
	// Load1 holds the value of the "Load1" field.
	Load1 float64 `json:"Load1,omitempty"`
	// Load5 holds the value of the "Load5" field.
	Load5 float64 `json:"Load5,omitempty"`
	// Load15 holds the value of the "Load15" field.
	Load15 float64 `json:"Load15,omitempty"`
	// TotalMem holds the value of the "TotalMem" field.
	TotalMem int64 `json:"TotalMem,omitempty"`
	// FreeMem holds the value of the "FreeMem" field.
	FreeMem int64 `json:"FreeMem,omitempty"`
	// UsedMem holds the value of the "UsedMem" field.
	UsedMem int64 `json:"UsedMem,omitempty"`
	// Timestamp holds the value of the "Timestamp" field.
	Timestamp int64 `json:"Timestamp,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the AgentStatusQuery when eager-loading is set.
	Edges AgentStatusEdges `json:"edges"`
}

// AgentStatusEdges holds the relations/edges for other nodes in the graph.
type AgentStatusEdges struct {
	// Host holds the value of the host edge.
	Host []*ProvisionedHost
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// HostOrErr returns the Host value or an error if the edge
// was not loaded in eager-loading.
func (e AgentStatusEdges) HostOrErr() ([]*ProvisionedHost, error) {
	if e.loadedTypes[0] {
		return e.Host, nil
	}
	return nil, &NotLoadedError{edge: "host"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*AgentStatus) scanValues() []interface{} {
	return []interface{}{
		&sql.NullInt64{},   // id
		&sql.NullString{},  // ClientID
		&sql.NullString{},  // Hostname
		&sql.NullInt64{},   // UpTime
		&sql.NullInt64{},   // BootTime
		&sql.NullInt64{},   // NumProcs
		&sql.NullString{},  // Os
		&sql.NullString{},  // HostID
		&sql.NullFloat64{}, // Load1
		&sql.NullFloat64{}, // Load5
		&sql.NullFloat64{}, // Load15
		&sql.NullInt64{},   // TotalMem
		&sql.NullInt64{},   // FreeMem
		&sql.NullInt64{},   // UsedMem
		&sql.NullInt64{},   // Timestamp
	}
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the AgentStatus fields.
func (as *AgentStatus) assignValues(values ...interface{}) error {
	if m, n := len(values), len(agentstatus.Columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	value, ok := values[0].(*sql.NullInt64)
	if !ok {
		return fmt.Errorf("unexpected type %T for field id", value)
	}
	as.ID = int(value.Int64)
	values = values[1:]
	if value, ok := values[0].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field ClientID", values[0])
	} else if value.Valid {
		as.ClientID = value.String
	}
	if value, ok := values[1].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field Hostname", values[1])
	} else if value.Valid {
		as.Hostname = value.String
	}
	if value, ok := values[2].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field UpTime", values[2])
	} else if value.Valid {
		as.UpTime = value.Int64
	}
	if value, ok := values[3].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field BootTime", values[3])
	} else if value.Valid {
		as.BootTime = value.Int64
	}
	if value, ok := values[4].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field NumProcs", values[4])
	} else if value.Valid {
		as.NumProcs = value.Int64
	}
	if value, ok := values[5].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field Os", values[5])
	} else if value.Valid {
		as.Os = value.String
	}
	if value, ok := values[6].(*sql.NullString); !ok {
		return fmt.Errorf("unexpected type %T for field HostID", values[6])
	} else if value.Valid {
		as.HostID = value.String
	}
	if value, ok := values[7].(*sql.NullFloat64); !ok {
		return fmt.Errorf("unexpected type %T for field Load1", values[7])
	} else if value.Valid {
		as.Load1 = value.Float64
	}
	if value, ok := values[8].(*sql.NullFloat64); !ok {
		return fmt.Errorf("unexpected type %T for field Load5", values[8])
	} else if value.Valid {
		as.Load5 = value.Float64
	}
	if value, ok := values[9].(*sql.NullFloat64); !ok {
		return fmt.Errorf("unexpected type %T for field Load15", values[9])
	} else if value.Valid {
		as.Load15 = value.Float64
	}
	if value, ok := values[10].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field TotalMem", values[10])
	} else if value.Valid {
		as.TotalMem = value.Int64
	}
	if value, ok := values[11].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field FreeMem", values[11])
	} else if value.Valid {
		as.FreeMem = value.Int64
	}
	if value, ok := values[12].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field UsedMem", values[12])
	} else if value.Valid {
		as.UsedMem = value.Int64
	}
	if value, ok := values[13].(*sql.NullInt64); !ok {
		return fmt.Errorf("unexpected type %T for field Timestamp", values[13])
	} else if value.Valid {
		as.Timestamp = value.Int64
	}
	return nil
}

// QueryHost queries the host edge of the AgentStatus.
func (as *AgentStatus) QueryHost() *ProvisionedHostQuery {
	return (&AgentStatusClient{config: as.config}).QueryHost(as)
}

// Update returns a builder for updating this AgentStatus.
// Note that, you need to call AgentStatus.Unwrap() before calling this method, if this AgentStatus
// was returned from a transaction, and the transaction was committed or rolled back.
func (as *AgentStatus) Update() *AgentStatusUpdateOne {
	return (&AgentStatusClient{config: as.config}).UpdateOne(as)
}

// Unwrap unwraps the entity that was returned from a transaction after it was closed,
// so that all next queries will be executed through the driver which created the transaction.
func (as *AgentStatus) Unwrap() *AgentStatus {
	tx, ok := as.config.driver.(*txDriver)
	if !ok {
		panic("ent: AgentStatus is not a transactional entity")
	}
	as.config.driver = tx.drv
	return as
}

// String implements the fmt.Stringer.
func (as *AgentStatus) String() string {
	var builder strings.Builder
	builder.WriteString("AgentStatus(")
	builder.WriteString(fmt.Sprintf("id=%v", as.ID))
	builder.WriteString(", ClientID=")
	builder.WriteString(as.ClientID)
	builder.WriteString(", Hostname=")
	builder.WriteString(as.Hostname)
	builder.WriteString(", UpTime=")
	builder.WriteString(fmt.Sprintf("%v", as.UpTime))
	builder.WriteString(", BootTime=")
	builder.WriteString(fmt.Sprintf("%v", as.BootTime))
	builder.WriteString(", NumProcs=")
	builder.WriteString(fmt.Sprintf("%v", as.NumProcs))
	builder.WriteString(", Os=")
	builder.WriteString(as.Os)
	builder.WriteString(", HostID=")
	builder.WriteString(as.HostID)
	builder.WriteString(", Load1=")
	builder.WriteString(fmt.Sprintf("%v", as.Load1))
	builder.WriteString(", Load5=")
	builder.WriteString(fmt.Sprintf("%v", as.Load5))
	builder.WriteString(", Load15=")
	builder.WriteString(fmt.Sprintf("%v", as.Load15))
	builder.WriteString(", TotalMem=")
	builder.WriteString(fmt.Sprintf("%v", as.TotalMem))
	builder.WriteString(", FreeMem=")
	builder.WriteString(fmt.Sprintf("%v", as.FreeMem))
	builder.WriteString(", UsedMem=")
	builder.WriteString(fmt.Sprintf("%v", as.UsedMem))
	builder.WriteString(", Timestamp=")
	builder.WriteString(fmt.Sprintf("%v", as.Timestamp))
	builder.WriteByte(')')
	return builder.String()
}

// AgentStatusSlice is a parsable slice of AgentStatus.
type AgentStatusSlice []*AgentStatus

func (as AgentStatusSlice) config(cfg config) {
	for _i := range as {
		as[_i].config = cfg
	}
}
