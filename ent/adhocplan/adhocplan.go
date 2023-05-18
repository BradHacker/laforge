// Code generated by ent, DO NOT EDIT.

package adhocplan

import (
	"github.com/google/uuid"
)

const (
	// Label holds the string label denoting the adhocplan type in the database.
	Label = "adhoc_plan"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// EdgePrevAdhocPlans holds the string denoting the prevadhocplans edge name in mutations.
	EdgePrevAdhocPlans = "PrevAdhocPlans"
	// EdgeNextAdhocPlans holds the string denoting the nextadhocplans edge name in mutations.
	EdgeNextAdhocPlans = "NextAdhocPlans"
	// EdgeBuild holds the string denoting the build edge name in mutations.
	EdgeBuild = "Build"
	// EdgeStatus holds the string denoting the status edge name in mutations.
	EdgeStatus = "Status"
	// EdgeAgentTask holds the string denoting the agenttask edge name in mutations.
	EdgeAgentTask = "AgentTask"
	// Table holds the table name of the adhocplan in the database.
	Table = "adhoc_plans"
	// PrevAdhocPlansTable is the table that holds the PrevAdhocPlans relation/edge. The primary key declared below.
	PrevAdhocPlansTable = "adhoc_plan_NextAdhocPlans"
	// NextAdhocPlansTable is the table that holds the NextAdhocPlans relation/edge. The primary key declared below.
	NextAdhocPlansTable = "adhoc_plan_NextAdhocPlans"
	// BuildTable is the table that holds the Build relation/edge.
	BuildTable = "adhoc_plans"
	// BuildInverseTable is the table name for the Build entity.
	// It exists in this package in order to avoid circular dependency with the "build" package.
	BuildInverseTable = "builds"
	// BuildColumn is the table column denoting the Build relation/edge.
	BuildColumn = "adhoc_plan_build"
	// StatusTable is the table that holds the Status relation/edge.
	StatusTable = "status"
	// StatusInverseTable is the table name for the Status entity.
	// It exists in this package in order to avoid circular dependency with the "status" package.
	StatusInverseTable = "status"
	// StatusColumn is the table column denoting the Status relation/edge.
	StatusColumn = "adhoc_plan_status"
	// AgentTaskTable is the table that holds the AgentTask relation/edge.
	AgentTaskTable = "adhoc_plans"
	// AgentTaskInverseTable is the table name for the AgentTask entity.
	// It exists in this package in order to avoid circular dependency with the "agenttask" package.
	AgentTaskInverseTable = "agent_tasks"
	// AgentTaskColumn is the table column denoting the AgentTask relation/edge.
	AgentTaskColumn = "adhoc_plan_agent_task"
)

// Columns holds all SQL columns for adhocplan fields.
var Columns = []string{
	FieldID,
}

// ForeignKeys holds the SQL foreign-keys that are owned by the "adhoc_plans"
// table and are not defined as standalone fields in the schema.
var ForeignKeys = []string{
	"adhoc_plan_build",
	"adhoc_plan_agent_task",
}

var (
	// PrevAdhocPlansPrimaryKey and PrevAdhocPlansColumn2 are the table columns denoting the
	// primary key for the PrevAdhocPlans relation (M2M).
	PrevAdhocPlansPrimaryKey = []string{"adhoc_plan_id", "PrevAdhocPlan_id"}
	// NextAdhocPlansPrimaryKey and NextAdhocPlansColumn2 are the table columns denoting the
	// primary key for the NextAdhocPlans relation (M2M).
	NextAdhocPlansPrimaryKey = []string{"adhoc_plan_id", "PrevAdhocPlan_id"}
)

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	for i := range ForeignKeys {
		if column == ForeignKeys[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() uuid.UUID
)
