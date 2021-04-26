// Code generated by entc, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/command"
	"github.com/gen0cide/laforge/ent/environment"
)

// Command is the model entity for the Command schema.
type Command struct {
	config ` json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// HclID holds the value of the "hcl_id" field.
	HclID string `json:"hcl_id,omitempty" hcl:"id,label"`
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty" hcl:"name,attr"`
	// Description holds the value of the "description" field.
	Description string `json:"description,omitempty" hcl:"description,attr"`
	// Program holds the value of the "program" field.
	Program string `json:"program,omitempty" hcl:"program,attr"`
	// Args holds the value of the "args" field.
	Args []string `json:"args,omitempty" hcl:"args,attr"`
	// IgnoreErrors holds the value of the "ignore_errors" field.
	IgnoreErrors bool `json:"ignore_errors,omitempty" hcl:"ignore_errors,attr"`
	// Disabled holds the value of the "disabled" field.
	Disabled bool `json:"disabled,omitempty" hcl:"disabled,attr"`
	// Cooldown holds the value of the "cooldown" field.
	Cooldown int `json:"cooldown,omitempty" hcl:"cooldown,attr"`
	// Timeout holds the value of the "timeout" field.
	Timeout int `json:"timeout,omitempty" hcl:"timeout,attr" `
	// Vars holds the value of the "vars" field.
	Vars map[string]string `json:"vars,omitempty" hcl:"vars,attr"`
	// Tags holds the value of the "tags" field.
	Tags map[string]string `json:"tags,omitempty" hcl:"tags,optional"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the CommandQuery when eager-loading is set.
	Edges CommandEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// CommandToUser holds the value of the CommandToUser edge.
	HCLCommandToUser []*User `json:"CommandToUser,omitempty" hcl:"maintainer,block"`
	// CommandToEnvironment holds the value of the CommandToEnvironment edge.
	HCLCommandToEnvironment *Environment `json:"CommandToEnvironment,omitempty"`
	//
	environment_environment_to_command *int
}

// CommandEdges holds the relations/edges for other nodes in the graph.
type CommandEdges struct {
	// CommandToUser holds the value of the CommandToUser edge.
	CommandToUser []*User `json:"CommandToUser,omitempty" hcl:"maintainer,block"`
	// CommandToEnvironment holds the value of the CommandToEnvironment edge.
	CommandToEnvironment *Environment `json:"CommandToEnvironment,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
}

// CommandToUserOrErr returns the CommandToUser value or an error if the edge
// was not loaded in eager-loading.
func (e CommandEdges) CommandToUserOrErr() ([]*User, error) {
	if e.loadedTypes[0] {
		return e.CommandToUser, nil
	}
	return nil, &NotLoadedError{edge: "CommandToUser"}
}

// CommandToEnvironmentOrErr returns the CommandToEnvironment value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e CommandEdges) CommandToEnvironmentOrErr() (*Environment, error) {
	if e.loadedTypes[1] {
		if e.CommandToEnvironment == nil {
			// The edge CommandToEnvironment was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: environment.Label}
		}
		return e.CommandToEnvironment, nil
	}
	return nil, &NotLoadedError{edge: "CommandToEnvironment"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Command) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case command.FieldArgs, command.FieldVars, command.FieldTags:
			values[i] = &[]byte{}
		case command.FieldIgnoreErrors, command.FieldDisabled:
			values[i] = &sql.NullBool{}
		case command.FieldID, command.FieldCooldown, command.FieldTimeout:
			values[i] = &sql.NullInt64{}
		case command.FieldHclID, command.FieldName, command.FieldDescription, command.FieldProgram:
			values[i] = &sql.NullString{}
		case command.ForeignKeys[0]: // environment_environment_to_command
			values[i] = &sql.NullInt64{}
		default:
			return nil, fmt.Errorf("unexpected column %q for type Command", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Command fields.
func (c *Command) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case command.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			c.ID = int(value.Int64)
		case command.FieldHclID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field hcl_id", values[i])
			} else if value.Valid {
				c.HclID = value.String
			}
		case command.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				c.Name = value.String
			}
		case command.FieldDescription:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field description", values[i])
			} else if value.Valid {
				c.Description = value.String
			}
		case command.FieldProgram:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field program", values[i])
			} else if value.Valid {
				c.Program = value.String
			}
		case command.FieldArgs:

			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field args", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &c.Args); err != nil {
					return fmt.Errorf("unmarshal field args: %v", err)
				}
			}
		case command.FieldIgnoreErrors:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field ignore_errors", values[i])
			} else if value.Valid {
				c.IgnoreErrors = value.Bool
			}
		case command.FieldDisabled:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field disabled", values[i])
			} else if value.Valid {
				c.Disabled = value.Bool
			}
		case command.FieldCooldown:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field cooldown", values[i])
			} else if value.Valid {
				c.Cooldown = int(value.Int64)
			}
		case command.FieldTimeout:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field timeout", values[i])
			} else if value.Valid {
				c.Timeout = int(value.Int64)
			}
		case command.FieldVars:

			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field vars", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &c.Vars); err != nil {
					return fmt.Errorf("unmarshal field vars: %v", err)
				}
			}
		case command.FieldTags:

			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field tags", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &c.Tags); err != nil {
					return fmt.Errorf("unmarshal field tags: %v", err)
				}
			}
		case command.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field environment_environment_to_command", value)
			} else if value.Valid {
				c.environment_environment_to_command = new(int)
				*c.environment_environment_to_command = int(value.Int64)
			}
		}
	}
	return nil
}

// QueryCommandToUser queries the "CommandToUser" edge of the Command entity.
func (c *Command) QueryCommandToUser() *UserQuery {
	return (&CommandClient{config: c.config}).QueryCommandToUser(c)
}

// QueryCommandToEnvironment queries the "CommandToEnvironment" edge of the Command entity.
func (c *Command) QueryCommandToEnvironment() *EnvironmentQuery {
	return (&CommandClient{config: c.config}).QueryCommandToEnvironment(c)
}

// Update returns a builder for updating this Command.
// Note that you need to call Command.Unwrap() before calling this method if this Command
// was returned from a transaction, and the transaction was committed or rolled back.
func (c *Command) Update() *CommandUpdateOne {
	return (&CommandClient{config: c.config}).UpdateOne(c)
}

// Unwrap unwraps the Command entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (c *Command) Unwrap() *Command {
	tx, ok := c.config.driver.(*txDriver)
	if !ok {
		panic("ent: Command is not a transactional entity")
	}
	c.config.driver = tx.drv
	return c
}

// String implements the fmt.Stringer.
func (c *Command) String() string {
	var builder strings.Builder
	builder.WriteString("Command(")
	builder.WriteString(fmt.Sprintf("id=%v", c.ID))
	builder.WriteString(", hcl_id=")
	builder.WriteString(c.HclID)
	builder.WriteString(", name=")
	builder.WriteString(c.Name)
	builder.WriteString(", description=")
	builder.WriteString(c.Description)
	builder.WriteString(", program=")
	builder.WriteString(c.Program)
	builder.WriteString(", args=")
	builder.WriteString(fmt.Sprintf("%v", c.Args))
	builder.WriteString(", ignore_errors=")
	builder.WriteString(fmt.Sprintf("%v", c.IgnoreErrors))
	builder.WriteString(", disabled=")
	builder.WriteString(fmt.Sprintf("%v", c.Disabled))
	builder.WriteString(", cooldown=")
	builder.WriteString(fmt.Sprintf("%v", c.Cooldown))
	builder.WriteString(", timeout=")
	builder.WriteString(fmt.Sprintf("%v", c.Timeout))
	builder.WriteString(", vars=")
	builder.WriteString(fmt.Sprintf("%v", c.Vars))
	builder.WriteString(", tags=")
	builder.WriteString(fmt.Sprintf("%v", c.Tags))
	builder.WriteByte(')')
	return builder.String()
}

// Commands is a parsable slice of Command.
type Commands []*Command

func (c Commands) config(cfg config) {
	for _i := range c {
		c[_i].config = cfg
	}
}
