// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/gen0cide/laforge/ent/team"
	"github.com/google/uuid"
)

// Team is the model entity for the Team schema.
type Team struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// TeamNumber holds the value of the "team_number" field.
	TeamNumber int `json:"team_number,omitempty"`
	// Vars holds the value of the "vars" field.
	Vars map[string]string `json:"vars,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the TeamQuery when eager-loading is set.
	Edges TeamEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// TeamToBuild holds the value of the TeamToBuild edge.
	HCLTeamToBuild *Build `json:"TeamToBuild,omitempty"`
	// TeamToStatus holds the value of the TeamToStatus edge.
	HCLTeamToStatus *Status `json:"TeamToStatus,omitempty"`
	// TeamToProvisionedNetwork holds the value of the TeamToProvisionedNetwork edge.
	HCLTeamToProvisionedNetwork []*ProvisionedNetwork `json:"TeamToProvisionedNetwork,omitempty"`
	// TeamToPlan holds the value of the TeamToPlan edge.
	HCLTeamToPlan *Plan `json:"TeamToPlan,omitempty"`
	//
	plan_team          *uuid.UUID
	team_team_to_build *uuid.UUID
}

// TeamEdges holds the relations/edges for other nodes in the graph.
type TeamEdges struct {
	// TeamToBuild holds the value of the TeamToBuild edge.
	TeamToBuild *Build `json:"TeamToBuild,omitempty"`
	// TeamToStatus holds the value of the TeamToStatus edge.
	TeamToStatus *Status `json:"TeamToStatus,omitempty"`
	// TeamToProvisionedNetwork holds the value of the TeamToProvisionedNetwork edge.
	TeamToProvisionedNetwork []*ProvisionedNetwork `json:"TeamToProvisionedNetwork,omitempty"`
	// TeamToPlan holds the value of the TeamToPlan edge.
	TeamToPlan *Plan `json:"TeamToPlan,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
}

// TeamToBuildOrErr returns the TeamToBuild value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TeamEdges) TeamToBuildOrErr() (*Build, error) {
	if e.loadedTypes[0] {
		if e.TeamToBuild == nil {
			// The edge TeamToBuild was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: build.Label}
		}
		return e.TeamToBuild, nil
	}
	return nil, &NotLoadedError{edge: "TeamToBuild"}
}

// TeamToStatusOrErr returns the TeamToStatus value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TeamEdges) TeamToStatusOrErr() (*Status, error) {
	if e.loadedTypes[1] {
		if e.TeamToStatus == nil {
			// The edge TeamToStatus was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: status.Label}
		}
		return e.TeamToStatus, nil
	}
	return nil, &NotLoadedError{edge: "TeamToStatus"}
}

// TeamToProvisionedNetworkOrErr returns the TeamToProvisionedNetwork value or an error if the edge
// was not loaded in eager-loading.
func (e TeamEdges) TeamToProvisionedNetworkOrErr() ([]*ProvisionedNetwork, error) {
	if e.loadedTypes[2] {
		return e.TeamToProvisionedNetwork, nil
	}
	return nil, &NotLoadedError{edge: "TeamToProvisionedNetwork"}
}

// TeamToPlanOrErr returns the TeamToPlan value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TeamEdges) TeamToPlanOrErr() (*Plan, error) {
	if e.loadedTypes[3] {
		if e.TeamToPlan == nil {
			// The edge TeamToPlan was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: plan.Label}
		}
		return e.TeamToPlan, nil
	}
	return nil, &NotLoadedError{edge: "TeamToPlan"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Team) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case team.FieldVars:
			values[i] = new([]byte)
		case team.FieldTeamNumber:
			values[i] = new(sql.NullInt64)
		case team.FieldID:
			values[i] = new(uuid.UUID)
		case team.ForeignKeys[0]: // plan_team
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case team.ForeignKeys[1]: // team_team_to_build
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type Team", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Team fields.
func (t *Team) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case team.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				t.ID = *value
			}
		case team.FieldTeamNumber:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field team_number", values[i])
			} else if value.Valid {
				t.TeamNumber = int(value.Int64)
			}
		case team.FieldVars:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field vars", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &t.Vars); err != nil {
					return fmt.Errorf("unmarshal field vars: %w", err)
				}
			}
		case team.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field plan_team", values[i])
			} else if value.Valid {
				t.plan_team = new(uuid.UUID)
				*t.plan_team = *value.S.(*uuid.UUID)
			}
		case team.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field team_team_to_build", values[i])
			} else if value.Valid {
				t.team_team_to_build = new(uuid.UUID)
				*t.team_team_to_build = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryTeamToBuild queries the "TeamToBuild" edge of the Team entity.
func (t *Team) QueryTeamToBuild() *BuildQuery {
	return (&TeamClient{config: t.config}).QueryTeamToBuild(t)
}

// QueryTeamToStatus queries the "TeamToStatus" edge of the Team entity.
func (t *Team) QueryTeamToStatus() *StatusQuery {
	return (&TeamClient{config: t.config}).QueryTeamToStatus(t)
}

// QueryTeamToProvisionedNetwork queries the "TeamToProvisionedNetwork" edge of the Team entity.
func (t *Team) QueryTeamToProvisionedNetwork() *ProvisionedNetworkQuery {
	return (&TeamClient{config: t.config}).QueryTeamToProvisionedNetwork(t)
}

// QueryTeamToPlan queries the "TeamToPlan" edge of the Team entity.
func (t *Team) QueryTeamToPlan() *PlanQuery {
	return (&TeamClient{config: t.config}).QueryTeamToPlan(t)
}

// Update returns a builder for updating this Team.
// Note that you need to call Team.Unwrap() before calling this method if this Team
// was returned from a transaction, and the transaction was committed or rolled back.
func (t *Team) Update() *TeamUpdateOne {
	return (&TeamClient{config: t.config}).UpdateOne(t)
}

// Unwrap unwraps the Team entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (t *Team) Unwrap() *Team {
	tx, ok := t.config.driver.(*txDriver)
	if !ok {
		panic("ent: Team is not a transactional entity")
	}
	t.config.driver = tx.drv
	return t
}

// String implements the fmt.Stringer.
func (t *Team) String() string {
	var builder strings.Builder
	builder.WriteString("Team(")
	builder.WriteString(fmt.Sprintf("id=%v", t.ID))
	builder.WriteString(", team_number=")
	builder.WriteString(fmt.Sprintf("%v", t.TeamNumber))
	builder.WriteString(", vars=")
	builder.WriteString(fmt.Sprintf("%v", t.Vars))
	builder.WriteByte(')')
	return builder.String()
}

// Teams is a parsable slice of Team.
type Teams []*Team

func (t Teams) config(cfg config) {
	for _i := range t {
		t[_i].config = cfg
	}
}
