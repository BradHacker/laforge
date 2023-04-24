// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/agentstatus"
	"github.com/gen0cide/laforge/ent/build"
	"github.com/gen0cide/laforge/ent/ginfilemiddleware"
	"github.com/gen0cide/laforge/ent/host"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisionednetwork"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/google/uuid"
)

// ProvisionedHost is the model entity for the ProvisionedHost schema.
type ProvisionedHost struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// SubnetIP holds the value of the "subnet_ip" field.
	SubnetIP string `json:"subnet_ip,omitempty"`
	// AddonType holds the value of the "addon_type" field.
	AddonType *provisionedhost.AddonType `json:"addon_type,omitempty"`
	// Vars holds the value of the "vars" field.
	Vars map[string]string `json:"vars,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ProvisionedHostQuery when eager-loading is set.
	Edges ProvisionedHostEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// Status holds the value of the Status edge.
	HCLStatus *Status `json:"Status,omitempty"`
	// ProvisionedNetwork holds the value of the ProvisionedNetwork edge.
	HCLProvisionedNetwork *ProvisionedNetwork `json:"ProvisionedNetwork,omitempty"`
	// Host holds the value of the Host edge.
	HCLHost *Host `json:"Host,omitempty"`
	// EndStepPlan holds the value of the EndStepPlan edge.
	HCLEndStepPlan *Plan `json:"EndStepPlan,omitempty"`
	// Build holds the value of the Build edge.
	HCLBuild *Build `json:"Build,omitempty"`
	// ProvisioningSteps holds the value of the ProvisioningSteps edge.
	HCLProvisioningSteps []*ProvisioningStep `json:"ProvisioningSteps,omitempty"`
	// ProvisioningScheduledSteps holds the value of the ProvisioningScheduledSteps edge.
	HCLProvisioningScheduledSteps []*ProvisioningScheduledStep `json:"ProvisioningScheduledSteps,omitempty"`
	// AgentStatus holds the value of the AgentStatus edge.
	HCLAgentStatus *AgentStatus `json:"AgentStatus,omitempty"`
	// AgentTasks holds the value of the AgentTasks edge.
	HCLAgentTasks []*AgentTask `json:"AgentTasks,omitempty"`
	// Plan holds the value of the Plan edge.
	HCLPlan *Plan `json:"Plan,omitempty"`
	// GinFileMiddleware holds the value of the GinFileMiddleware edge.
	HCLGinFileMiddleware *GinFileMiddleware `json:"GinFileMiddleware,omitempty"`
	//
	agent_status_provisioned_host        *uuid.UUID
	gin_file_middleware_provisioned_host *uuid.UUID
	plan_provisioned_host                *uuid.UUID
	provisioned_host_provisioned_network *uuid.UUID
	provisioned_host_host                *uuid.UUID
	provisioned_host_end_step_plan       *uuid.UUID
	provisioned_host_build               *uuid.UUID
}

// ProvisionedHostEdges holds the relations/edges for other nodes in the graph.
type ProvisionedHostEdges struct {
	// Status holds the value of the Status edge.
	Status *Status `json:"Status,omitempty"`
	// ProvisionedNetwork holds the value of the ProvisionedNetwork edge.
	ProvisionedNetwork *ProvisionedNetwork `json:"ProvisionedNetwork,omitempty"`
	// Host holds the value of the Host edge.
	Host *Host `json:"Host,omitempty"`
	// EndStepPlan holds the value of the EndStepPlan edge.
	EndStepPlan *Plan `json:"EndStepPlan,omitempty"`
	// Build holds the value of the Build edge.
	Build *Build `json:"Build,omitempty"`
	// ProvisioningSteps holds the value of the ProvisioningSteps edge.
	ProvisioningSteps []*ProvisioningStep `json:"ProvisioningSteps,omitempty"`
	// ProvisioningScheduledSteps holds the value of the ProvisioningScheduledSteps edge.
	ProvisioningScheduledSteps []*ProvisioningScheduledStep `json:"ProvisioningScheduledSteps,omitempty"`
	// AgentStatus holds the value of the AgentStatus edge.
	AgentStatus *AgentStatus `json:"AgentStatus,omitempty"`
	// AgentTasks holds the value of the AgentTasks edge.
	AgentTasks []*AgentTask `json:"AgentTasks,omitempty"`
	// Plan holds the value of the Plan edge.
	Plan *Plan `json:"Plan,omitempty"`
	// GinFileMiddleware holds the value of the GinFileMiddleware edge.
	GinFileMiddleware *GinFileMiddleware `json:"GinFileMiddleware,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [11]bool
}

// StatusOrErr returns the Status value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) StatusOrErr() (*Status, error) {
	if e.loadedTypes[0] {
		if e.Status == nil {
			// The edge Status was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: status.Label}
		}
		return e.Status, nil
	}
	return nil, &NotLoadedError{edge: "Status"}
}

// ProvisionedNetworkOrErr returns the ProvisionedNetwork value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) ProvisionedNetworkOrErr() (*ProvisionedNetwork, error) {
	if e.loadedTypes[1] {
		if e.ProvisionedNetwork == nil {
			// The edge ProvisionedNetwork was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: provisionednetwork.Label}
		}
		return e.ProvisionedNetwork, nil
	}
	return nil, &NotLoadedError{edge: "ProvisionedNetwork"}
}

// HostOrErr returns the Host value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) HostOrErr() (*Host, error) {
	if e.loadedTypes[2] {
		if e.Host == nil {
			// The edge Host was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: host.Label}
		}
		return e.Host, nil
	}
	return nil, &NotLoadedError{edge: "Host"}
}

// EndStepPlanOrErr returns the EndStepPlan value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) EndStepPlanOrErr() (*Plan, error) {
	if e.loadedTypes[3] {
		if e.EndStepPlan == nil {
			// The edge EndStepPlan was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: plan.Label}
		}
		return e.EndStepPlan, nil
	}
	return nil, &NotLoadedError{edge: "EndStepPlan"}
}

// BuildOrErr returns the Build value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) BuildOrErr() (*Build, error) {
	if e.loadedTypes[4] {
		if e.Build == nil {
			// The edge Build was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: build.Label}
		}
		return e.Build, nil
	}
	return nil, &NotLoadedError{edge: "Build"}
}

// ProvisioningStepsOrErr returns the ProvisioningSteps value or an error if the edge
// was not loaded in eager-loading.
func (e ProvisionedHostEdges) ProvisioningStepsOrErr() ([]*ProvisioningStep, error) {
	if e.loadedTypes[5] {
		return e.ProvisioningSteps, nil
	}
	return nil, &NotLoadedError{edge: "ProvisioningSteps"}
}

// ProvisioningScheduledStepsOrErr returns the ProvisioningScheduledSteps value or an error if the edge
// was not loaded in eager-loading.
func (e ProvisionedHostEdges) ProvisioningScheduledStepsOrErr() ([]*ProvisioningScheduledStep, error) {
	if e.loadedTypes[6] {
		return e.ProvisioningScheduledSteps, nil
	}
	return nil, &NotLoadedError{edge: "ProvisioningScheduledSteps"}
}

// AgentStatusOrErr returns the AgentStatus value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) AgentStatusOrErr() (*AgentStatus, error) {
	if e.loadedTypes[7] {
		if e.AgentStatus == nil {
			// The edge AgentStatus was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: agentstatus.Label}
		}
		return e.AgentStatus, nil
	}
	return nil, &NotLoadedError{edge: "AgentStatus"}
}

// AgentTasksOrErr returns the AgentTasks value or an error if the edge
// was not loaded in eager-loading.
func (e ProvisionedHostEdges) AgentTasksOrErr() ([]*AgentTask, error) {
	if e.loadedTypes[8] {
		return e.AgentTasks, nil
	}
	return nil, &NotLoadedError{edge: "AgentTasks"}
}

// PlanOrErr returns the Plan value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) PlanOrErr() (*Plan, error) {
	if e.loadedTypes[9] {
		if e.Plan == nil {
			// The edge Plan was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: plan.Label}
		}
		return e.Plan, nil
	}
	return nil, &NotLoadedError{edge: "Plan"}
}

// GinFileMiddlewareOrErr returns the GinFileMiddleware value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisionedHostEdges) GinFileMiddlewareOrErr() (*GinFileMiddleware, error) {
	if e.loadedTypes[10] {
		if e.GinFileMiddleware == nil {
			// The edge GinFileMiddleware was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: ginfilemiddleware.Label}
		}
		return e.GinFileMiddleware, nil
	}
	return nil, &NotLoadedError{edge: "GinFileMiddleware"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*ProvisionedHost) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case provisionedhost.FieldVars:
			values[i] = new([]byte)
		case provisionedhost.FieldSubnetIP, provisionedhost.FieldAddonType:
			values[i] = new(sql.NullString)
		case provisionedhost.FieldID:
			values[i] = new(uuid.UUID)
		case provisionedhost.ForeignKeys[0]: // agent_status_provisioned_host
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisionedhost.ForeignKeys[1]: // gin_file_middleware_provisioned_host
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisionedhost.ForeignKeys[2]: // plan_provisioned_host
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisionedhost.ForeignKeys[3]: // provisioned_host_provisioned_network
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisionedhost.ForeignKeys[4]: // provisioned_host_host
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisionedhost.ForeignKeys[5]: // provisioned_host_end_step_plan
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisionedhost.ForeignKeys[6]: // provisioned_host_build
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type ProvisionedHost", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ProvisionedHost fields.
func (ph *ProvisionedHost) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case provisionedhost.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ph.ID = *value
			}
		case provisionedhost.FieldSubnetIP:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field subnet_ip", values[i])
			} else if value.Valid {
				ph.SubnetIP = value.String
			}
		case provisionedhost.FieldAddonType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field addon_type", values[i])
			} else if value.Valid {
				ph.AddonType = new(provisionedhost.AddonType)
				*ph.AddonType = provisionedhost.AddonType(value.String)
			}
		case provisionedhost.FieldVars:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field vars", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ph.Vars); err != nil {
					return fmt.Errorf("unmarshal field vars: %w", err)
				}
			}
		case provisionedhost.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field agent_status_provisioned_host", values[i])
			} else if value.Valid {
				ph.agent_status_provisioned_host = new(uuid.UUID)
				*ph.agent_status_provisioned_host = *value.S.(*uuid.UUID)
			}
		case provisionedhost.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field gin_file_middleware_provisioned_host", values[i])
			} else if value.Valid {
				ph.gin_file_middleware_provisioned_host = new(uuid.UUID)
				*ph.gin_file_middleware_provisioned_host = *value.S.(*uuid.UUID)
			}
		case provisionedhost.ForeignKeys[2]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field plan_provisioned_host", values[i])
			} else if value.Valid {
				ph.plan_provisioned_host = new(uuid.UUID)
				*ph.plan_provisioned_host = *value.S.(*uuid.UUID)
			}
		case provisionedhost.ForeignKeys[3]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioned_host_provisioned_network", values[i])
			} else if value.Valid {
				ph.provisioned_host_provisioned_network = new(uuid.UUID)
				*ph.provisioned_host_provisioned_network = *value.S.(*uuid.UUID)
			}
		case provisionedhost.ForeignKeys[4]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioned_host_host", values[i])
			} else if value.Valid {
				ph.provisioned_host_host = new(uuid.UUID)
				*ph.provisioned_host_host = *value.S.(*uuid.UUID)
			}
		case provisionedhost.ForeignKeys[5]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioned_host_end_step_plan", values[i])
			} else if value.Valid {
				ph.provisioned_host_end_step_plan = new(uuid.UUID)
				*ph.provisioned_host_end_step_plan = *value.S.(*uuid.UUID)
			}
		case provisionedhost.ForeignKeys[6]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioned_host_build", values[i])
			} else if value.Valid {
				ph.provisioned_host_build = new(uuid.UUID)
				*ph.provisioned_host_build = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryStatus queries the "Status" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryStatus() *StatusQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryStatus(ph)
}

// QueryProvisionedNetwork queries the "ProvisionedNetwork" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryProvisionedNetwork() *ProvisionedNetworkQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryProvisionedNetwork(ph)
}

// QueryHost queries the "Host" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryHost() *HostQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryHost(ph)
}

// QueryEndStepPlan queries the "EndStepPlan" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryEndStepPlan() *PlanQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryEndStepPlan(ph)
}

// QueryBuild queries the "Build" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryBuild() *BuildQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryBuild(ph)
}

// QueryProvisioningSteps queries the "ProvisioningSteps" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryProvisioningSteps() *ProvisioningStepQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryProvisioningSteps(ph)
}

// QueryProvisioningScheduledSteps queries the "ProvisioningScheduledSteps" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryProvisioningScheduledSteps() *ProvisioningScheduledStepQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryProvisioningScheduledSteps(ph)
}

// QueryAgentStatus queries the "AgentStatus" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryAgentStatus() *AgentStatusQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryAgentStatus(ph)
}

// QueryAgentTasks queries the "AgentTasks" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryAgentTasks() *AgentTaskQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryAgentTasks(ph)
}

// QueryPlan queries the "Plan" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryPlan() *PlanQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryPlan(ph)
}

// QueryGinFileMiddleware queries the "GinFileMiddleware" edge of the ProvisionedHost entity.
func (ph *ProvisionedHost) QueryGinFileMiddleware() *GinFileMiddlewareQuery {
	return (&ProvisionedHostClient{config: ph.config}).QueryGinFileMiddleware(ph)
}

// Update returns a builder for updating this ProvisionedHost.
// Note that you need to call ProvisionedHost.Unwrap() before calling this method if this ProvisionedHost
// was returned from a transaction, and the transaction was committed or rolled back.
func (ph *ProvisionedHost) Update() *ProvisionedHostUpdateOne {
	return (&ProvisionedHostClient{config: ph.config}).UpdateOne(ph)
}

// Unwrap unwraps the ProvisionedHost entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ph *ProvisionedHost) Unwrap() *ProvisionedHost {
	tx, ok := ph.config.driver.(*txDriver)
	if !ok {
		panic("ent: ProvisionedHost is not a transactional entity")
	}
	ph.config.driver = tx.drv
	return ph
}

// String implements the fmt.Stringer.
func (ph *ProvisionedHost) String() string {
	var builder strings.Builder
	builder.WriteString("ProvisionedHost(")
	builder.WriteString(fmt.Sprintf("id=%v", ph.ID))
	builder.WriteString(", subnet_ip=")
	builder.WriteString(ph.SubnetIP)
	if v := ph.AddonType; v != nil {
		builder.WriteString(", addon_type=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", vars=")
	builder.WriteString(fmt.Sprintf("%v", ph.Vars))
	builder.WriteByte(')')
	return builder.String()
}

// ProvisionedHosts is a parsable slice of ProvisionedHost.
type ProvisionedHosts []*ProvisionedHost

func (ph ProvisionedHosts) config(cfg config) {
	for _i := range ph {
		ph[_i].config = cfg
	}
}
