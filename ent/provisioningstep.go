// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/ansible"
	"github.com/gen0cide/laforge/ent/command"
	"github.com/gen0cide/laforge/ent/dnsrecord"
	"github.com/gen0cide/laforge/ent/filedelete"
	"github.com/gen0cide/laforge/ent/filedownload"
	"github.com/gen0cide/laforge/ent/fileextract"
	"github.com/gen0cide/laforge/ent/ginfilemiddleware"
	"github.com/gen0cide/laforge/ent/plan"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisioningstep"
	"github.com/gen0cide/laforge/ent/script"
	"github.com/gen0cide/laforge/ent/status"
	"github.com/google/uuid"
)

// ProvisioningStep is the model entity for the ProvisioningStep schema.
type ProvisioningStep struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// Type holds the value of the "type" field.
	Type provisioningstep.Type `json:"type,omitempty"`
	// StepNumber holds the value of the "step_number" field.
	StepNumber int `json:"step_number,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the ProvisioningStepQuery when eager-loading is set.
	Edges ProvisioningStepEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// Status holds the value of the Status edge.
	HCLStatus *Status `json:"Status,omitempty"`
	// ProvisionedHost holds the value of the ProvisionedHost edge.
	HCLProvisionedHost *ProvisionedHost `json:"ProvisionedHost,omitempty"`
	// Script holds the value of the Script edge.
	HCLScript *Script `json:"Script,omitempty"`
	// Command holds the value of the Command edge.
	HCLCommand *Command `json:"Command,omitempty"`
	// DNSRecord holds the value of the DNSRecord edge.
	HCLDNSRecord *DNSRecord `json:"DNSRecord,omitempty"`
	// FileDelete holds the value of the FileDelete edge.
	HCLFileDelete *FileDelete `json:"FileDelete,omitempty"`
	// FileDownload holds the value of the FileDownload edge.
	HCLFileDownload *FileDownload `json:"FileDownload,omitempty"`
	// FileExtract holds the value of the FileExtract edge.
	HCLFileExtract *FileExtract `json:"FileExtract,omitempty"`
	// Ansible holds the value of the Ansible edge.
	HCLAnsible *Ansible `json:"Ansible,omitempty"`
	// Plan holds the value of the Plan edge.
	HCLPlan *Plan `json:"Plan,omitempty"`
	// AgentTasks holds the value of the AgentTasks edge.
	HCLAgentTasks []*AgentTask `json:"AgentTasks,omitempty"`
	// GinFileMiddleware holds the value of the GinFileMiddleware edge.
	HCLGinFileMiddleware *GinFileMiddleware `json:"GinFileMiddleware,omitempty"`
	//
	gin_file_middleware_provisioning_step *uuid.UUID
	plan_provisioning_step                *uuid.UUID
	provisioning_step_provisioned_host    *uuid.UUID
	provisioning_step_script              *uuid.UUID
	provisioning_step_command             *uuid.UUID
	provisioning_step_dns_record          *uuid.UUID
	provisioning_step_file_delete         *uuid.UUID
	provisioning_step_file_download       *uuid.UUID
	provisioning_step_file_extract        *uuid.UUID
	provisioning_step_ansible             *uuid.UUID
}

// ProvisioningStepEdges holds the relations/edges for other nodes in the graph.
type ProvisioningStepEdges struct {
	// Status holds the value of the Status edge.
	Status *Status `json:"Status,omitempty"`
	// ProvisionedHost holds the value of the ProvisionedHost edge.
	ProvisionedHost *ProvisionedHost `json:"ProvisionedHost,omitempty"`
	// Script holds the value of the Script edge.
	Script *Script `json:"Script,omitempty"`
	// Command holds the value of the Command edge.
	Command *Command `json:"Command,omitempty"`
	// DNSRecord holds the value of the DNSRecord edge.
	DNSRecord *DNSRecord `json:"DNSRecord,omitempty"`
	// FileDelete holds the value of the FileDelete edge.
	FileDelete *FileDelete `json:"FileDelete,omitempty"`
	// FileDownload holds the value of the FileDownload edge.
	FileDownload *FileDownload `json:"FileDownload,omitempty"`
	// FileExtract holds the value of the FileExtract edge.
	FileExtract *FileExtract `json:"FileExtract,omitempty"`
	// Ansible holds the value of the Ansible edge.
	Ansible *Ansible `json:"Ansible,omitempty"`
	// Plan holds the value of the Plan edge.
	Plan *Plan `json:"Plan,omitempty"`
	// AgentTasks holds the value of the AgentTasks edge.
	AgentTasks []*AgentTask `json:"AgentTasks,omitempty"`
	// GinFileMiddleware holds the value of the GinFileMiddleware edge.
	GinFileMiddleware *GinFileMiddleware `json:"GinFileMiddleware,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [12]bool
}

// StatusOrErr returns the Status value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) StatusOrErr() (*Status, error) {
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

// ProvisionedHostOrErr returns the ProvisionedHost value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) ProvisionedHostOrErr() (*ProvisionedHost, error) {
	if e.loadedTypes[1] {
		if e.ProvisionedHost == nil {
			// The edge ProvisionedHost was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: provisionedhost.Label}
		}
		return e.ProvisionedHost, nil
	}
	return nil, &NotLoadedError{edge: "ProvisionedHost"}
}

// ScriptOrErr returns the Script value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) ScriptOrErr() (*Script, error) {
	if e.loadedTypes[2] {
		if e.Script == nil {
			// The edge Script was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: script.Label}
		}
		return e.Script, nil
	}
	return nil, &NotLoadedError{edge: "Script"}
}

// CommandOrErr returns the Command value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) CommandOrErr() (*Command, error) {
	if e.loadedTypes[3] {
		if e.Command == nil {
			// The edge Command was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: command.Label}
		}
		return e.Command, nil
	}
	return nil, &NotLoadedError{edge: "Command"}
}

// DNSRecordOrErr returns the DNSRecord value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) DNSRecordOrErr() (*DNSRecord, error) {
	if e.loadedTypes[4] {
		if e.DNSRecord == nil {
			// The edge DNSRecord was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: dnsrecord.Label}
		}
		return e.DNSRecord, nil
	}
	return nil, &NotLoadedError{edge: "DNSRecord"}
}

// FileDeleteOrErr returns the FileDelete value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) FileDeleteOrErr() (*FileDelete, error) {
	if e.loadedTypes[5] {
		if e.FileDelete == nil {
			// The edge FileDelete was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: filedelete.Label}
		}
		return e.FileDelete, nil
	}
	return nil, &NotLoadedError{edge: "FileDelete"}
}

// FileDownloadOrErr returns the FileDownload value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) FileDownloadOrErr() (*FileDownload, error) {
	if e.loadedTypes[6] {
		if e.FileDownload == nil {
			// The edge FileDownload was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: filedownload.Label}
		}
		return e.FileDownload, nil
	}
	return nil, &NotLoadedError{edge: "FileDownload"}
}

// FileExtractOrErr returns the FileExtract value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) FileExtractOrErr() (*FileExtract, error) {
	if e.loadedTypes[7] {
		if e.FileExtract == nil {
			// The edge FileExtract was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: fileextract.Label}
		}
		return e.FileExtract, nil
	}
	return nil, &NotLoadedError{edge: "FileExtract"}
}

// AnsibleOrErr returns the Ansible value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) AnsibleOrErr() (*Ansible, error) {
	if e.loadedTypes[8] {
		if e.Ansible == nil {
			// The edge Ansible was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: ansible.Label}
		}
		return e.Ansible, nil
	}
	return nil, &NotLoadedError{edge: "Ansible"}
}

// PlanOrErr returns the Plan value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) PlanOrErr() (*Plan, error) {
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

// AgentTasksOrErr returns the AgentTasks value or an error if the edge
// was not loaded in eager-loading.
func (e ProvisioningStepEdges) AgentTasksOrErr() ([]*AgentTask, error) {
	if e.loadedTypes[10] {
		return e.AgentTasks, nil
	}
	return nil, &NotLoadedError{edge: "AgentTasks"}
}

// GinFileMiddlewareOrErr returns the GinFileMiddleware value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e ProvisioningStepEdges) GinFileMiddlewareOrErr() (*GinFileMiddleware, error) {
	if e.loadedTypes[11] {
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
func (*ProvisioningStep) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case provisioningstep.FieldStepNumber:
			values[i] = new(sql.NullInt64)
		case provisioningstep.FieldType:
			values[i] = new(sql.NullString)
		case provisioningstep.FieldID:
			values[i] = new(uuid.UUID)
		case provisioningstep.ForeignKeys[0]: // gin_file_middleware_provisioning_step
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[1]: // plan_provisioning_step
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[2]: // provisioning_step_provisioned_host
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[3]: // provisioning_step_script
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[4]: // provisioning_step_command
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[5]: // provisioning_step_dns_record
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[6]: // provisioning_step_file_delete
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[7]: // provisioning_step_file_download
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[8]: // provisioning_step_file_extract
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case provisioningstep.ForeignKeys[9]: // provisioning_step_ansible
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			return nil, fmt.Errorf("unexpected column %q for type ProvisioningStep", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the ProvisioningStep fields.
func (ps *ProvisioningStep) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case provisioningstep.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ps.ID = *value
			}
		case provisioningstep.FieldType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field type", values[i])
			} else if value.Valid {
				ps.Type = provisioningstep.Type(value.String)
			}
		case provisioningstep.FieldStepNumber:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field step_number", values[i])
			} else if value.Valid {
				ps.StepNumber = int(value.Int64)
			}
		case provisioningstep.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field gin_file_middleware_provisioning_step", values[i])
			} else if value.Valid {
				ps.gin_file_middleware_provisioning_step = new(uuid.UUID)
				*ps.gin_file_middleware_provisioning_step = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field plan_provisioning_step", values[i])
			} else if value.Valid {
				ps.plan_provisioning_step = new(uuid.UUID)
				*ps.plan_provisioning_step = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[2]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_provisioned_host", values[i])
			} else if value.Valid {
				ps.provisioning_step_provisioned_host = new(uuid.UUID)
				*ps.provisioning_step_provisioned_host = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[3]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_script", values[i])
			} else if value.Valid {
				ps.provisioning_step_script = new(uuid.UUID)
				*ps.provisioning_step_script = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[4]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_command", values[i])
			} else if value.Valid {
				ps.provisioning_step_command = new(uuid.UUID)
				*ps.provisioning_step_command = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[5]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_dns_record", values[i])
			} else if value.Valid {
				ps.provisioning_step_dns_record = new(uuid.UUID)
				*ps.provisioning_step_dns_record = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[6]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_file_delete", values[i])
			} else if value.Valid {
				ps.provisioning_step_file_delete = new(uuid.UUID)
				*ps.provisioning_step_file_delete = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[7]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_file_download", values[i])
			} else if value.Valid {
				ps.provisioning_step_file_download = new(uuid.UUID)
				*ps.provisioning_step_file_download = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[8]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_file_extract", values[i])
			} else if value.Valid {
				ps.provisioning_step_file_extract = new(uuid.UUID)
				*ps.provisioning_step_file_extract = *value.S.(*uuid.UUID)
			}
		case provisioningstep.ForeignKeys[9]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field provisioning_step_ansible", values[i])
			} else if value.Valid {
				ps.provisioning_step_ansible = new(uuid.UUID)
				*ps.provisioning_step_ansible = *value.S.(*uuid.UUID)
			}
		}
	}
	return nil
}

// QueryStatus queries the "Status" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryStatus() *StatusQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryStatus(ps)
}

// QueryProvisionedHost queries the "ProvisionedHost" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryProvisionedHost() *ProvisionedHostQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryProvisionedHost(ps)
}

// QueryScript queries the "Script" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryScript() *ScriptQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryScript(ps)
}

// QueryCommand queries the "Command" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryCommand() *CommandQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryCommand(ps)
}

// QueryDNSRecord queries the "DNSRecord" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryDNSRecord() *DNSRecordQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryDNSRecord(ps)
}

// QueryFileDelete queries the "FileDelete" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryFileDelete() *FileDeleteQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryFileDelete(ps)
}

// QueryFileDownload queries the "FileDownload" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryFileDownload() *FileDownloadQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryFileDownload(ps)
}

// QueryFileExtract queries the "FileExtract" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryFileExtract() *FileExtractQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryFileExtract(ps)
}

// QueryAnsible queries the "Ansible" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryAnsible() *AnsibleQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryAnsible(ps)
}

// QueryPlan queries the "Plan" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryPlan() *PlanQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryPlan(ps)
}

// QueryAgentTasks queries the "AgentTasks" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryAgentTasks() *AgentTaskQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryAgentTasks(ps)
}

// QueryGinFileMiddleware queries the "GinFileMiddleware" edge of the ProvisioningStep entity.
func (ps *ProvisioningStep) QueryGinFileMiddleware() *GinFileMiddlewareQuery {
	return (&ProvisioningStepClient{config: ps.config}).QueryGinFileMiddleware(ps)
}

// Update returns a builder for updating this ProvisioningStep.
// Note that you need to call ProvisioningStep.Unwrap() before calling this method if this ProvisioningStep
// was returned from a transaction, and the transaction was committed or rolled back.
func (ps *ProvisioningStep) Update() *ProvisioningStepUpdateOne {
	return (&ProvisioningStepClient{config: ps.config}).UpdateOne(ps)
}

// Unwrap unwraps the ProvisioningStep entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ps *ProvisioningStep) Unwrap() *ProvisioningStep {
	tx, ok := ps.config.driver.(*txDriver)
	if !ok {
		panic("ent: ProvisioningStep is not a transactional entity")
	}
	ps.config.driver = tx.drv
	return ps
}

// String implements the fmt.Stringer.
func (ps *ProvisioningStep) String() string {
	var builder strings.Builder
	builder.WriteString("ProvisioningStep(")
	builder.WriteString(fmt.Sprintf("id=%v", ps.ID))
	builder.WriteString(", type=")
	builder.WriteString(fmt.Sprintf("%v", ps.Type))
	builder.WriteString(", step_number=")
	builder.WriteString(fmt.Sprintf("%v", ps.StepNumber))
	builder.WriteByte(')')
	return builder.String()
}

// ProvisioningSteps is a parsable slice of ProvisioningStep.
type ProvisioningSteps []*ProvisioningStep

func (ps ProvisioningSteps) config(cfg config) {
	for _i := range ps {
		ps[_i].config = cfg
	}
}
