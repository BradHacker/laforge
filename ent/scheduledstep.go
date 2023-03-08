// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/environment"
	"github.com/gen0cide/laforge/ent/scheduledstep"
	"github.com/google/uuid"
)

// ScheduledStep is the model entity for the ScheduledStep schema.
type ScheduledStep struct {
	config ` json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// HclID holds the value of the "hcl_id" field.
	HclID string `json:"hcl_id,omitempty" hcl:"id,label"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty" hcl:"name,attr"`
	// Description holds the value of the "description" field.
	Description string `json:"description,omitempty" hcl:"description,optional"`
	// Step holds the value of the "step" field.
	Step string `json:"step,omitempty" hcl:"step,attr"`
	// Type holds the value of the "type" field.
	Type scheduledstep.Type `json:"type,omitempty" hcl:"type,attr"`
	// Schedule holds the value of the "schedule" field.
	Schedule string `json:"schedule,omitempty" hcl:"schedule,optional"`
	// RunAt holds the value of the "run_at" field.
	RunAt string `json:"run_at,omitempty" hcl:"run_at,optional"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ScheduledStepQuery when eager-loading is set.
	Edges ScheduledStepEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// ScheduledStepToEnvironment holds the value of the ScheduledStepToEnvironment edge.
	HCLScheduledStepToEnvironment *Environment `json:"ScheduledStepToEnvironment,omitempty"`
	//
	environment_environment_to_scheduled_step *uuid.UUID
}

// ScheduledStepEdges holds the relations/edges for other nodes in the graph.
type ScheduledStepEdges struct {
	// ScheduledStepToEnvironment holds the value of the ScheduledStepToEnvironment edge.
	ScheduledStepToEnvironment *Environment `json:"ScheduledStepToEnvironment,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// ScheduledStepToEnvironmentOrErr returns the ScheduledStepToEnvironment value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ScheduledStepEdges) ScheduledStepToEnvironmentOrErr() (*Environment, error) {
	if e.loadedTypes[0] {
		if e.ScheduledStepToEnvironment == nil {
			// The edge ScheduledStepToEnvironment was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: environment.Label}
		}
		return e.ScheduledStepToEnvironment, nil
	}
	return nil, &NotLoadedError{edge: "ScheduledStepToEnvironment"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*ScheduledStep) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case scheduledstep.FieldHclID, scheduledstep.FieldName, scheduledstep.FieldDescription, scheduledstep.FieldStep, scheduledstep.FieldType, scheduledstep.FieldSchedule, scheduledstep.FieldRunAt:
			values[i] = new(sql.NullString)
		case scheduledstep.FieldID:
			values[i] = new(uuid.UUID)
		case scheduledstep.ForeignKeys[0]: // environment_environment_to_scheduled_step
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type ScheduledStep", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ScheduledStep fields.
func (ss *ScheduledStep) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case scheduledstep.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ss.ID = *value
			}
		case scheduledstep.FieldHclID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field hcl_id", values[i])
			} else if value.Valid {
				ss.HclID = value.String
			}
		case scheduledstep.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				ss.Name = value.String
			}
		case scheduledstep.FieldDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field description", values[i])
			} else if value.Valid {
				ss.Description = value.String
			}
		case scheduledstep.FieldStep:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field step", values[i])
			} else if value.Valid {
				ss.Step = value.String
			}
		case scheduledstep.FieldType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field type", values[i])
			} else if value.Valid {
				ss.Type = scheduledstep.Type(value.String)
			}
		case scheduledstep.FieldSchedule:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field schedule", values[i])
			} else if value.Valid {
				ss.Schedule = value.String
			}
		case scheduledstep.FieldRunAt:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field run_at", values[i])
			} else if value.Valid {
				ss.RunAt = value.String
			}
		case scheduledstep.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field environment_environment_to_scheduled_step", values[i])
			} else if value.Valid {
				ss.environment_environment_to_scheduled_step = new(uuid.UUID)
				*ss.environment_environment_to_scheduled_step = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryScheduledStepToEnvironment queries the "ScheduledStepToEnvironment" edge of the ScheduledStep entity.
func (ss *ScheduledStep) QueryScheduledStepToEnvironment() *EnvironmentQuery {
	return (&ScheduledStepClient{config: ss.config}).QueryScheduledStepToEnvironment(ss)
}

// Update returns a builder for updating this ScheduledStep.
// Note that you need to call ScheduledStep.Unwrap() before calling this method if this ScheduledStep
// was returned from a transaction, and the transaction was committed or rolled back.
func (ss *ScheduledStep) Update() *ScheduledStepUpdateOne {
	return (&ScheduledStepClient{config: ss.config}).UpdateOne(ss)
}

// Unwrap unwraps the ScheduledStep entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ss *ScheduledStep) Unwrap() *ScheduledStep {
	tx, ok := ss.config.driver.(*txDriver)
	if !ok {
		panic("ent: ScheduledStep is not a transactional entity")
	}
	ss.config.driver = tx.drv
	return ss
}

// String implements the fmt.Stringer.
func (ss *ScheduledStep) String() string {
	var builder strings.Builder
	builder.WriteString("ScheduledStep(")
	builder.WriteString(fmt.Sprintf("id=%v", ss.ID))
	builder.WriteString(", hcl_id=")
	builder.WriteString(ss.HclID)
	builder.WriteString(", name=")
	builder.WriteString(ss.Name)
	builder.WriteString(", description=")
	builder.WriteString(ss.Description)
	builder.WriteString(", step=")
	builder.WriteString(ss.Step)
	builder.WriteString(", type=")
	builder.WriteString(fmt.Sprintf("%v", ss.Type))
	builder.WriteString(", schedule=")
	builder.WriteString(ss.Schedule)
	builder.WriteString(", run_at=")
	builder.WriteString(ss.RunAt)
	builder.WriteByte(')')
	return builder.String()
}

// ScheduledSteps is a parsable slice of ScheduledStep.
type ScheduledSteps []*ScheduledStep

func (ss ScheduledSteps) config(cfg config) {
	for _i := range ss {
		ss[_i].config = cfg
	}
}
