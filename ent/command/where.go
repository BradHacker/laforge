// Code generated by ent, DO NOT EDIT.

package command

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/gen0cide/laforge/ent/predicate"
	"github.com/google/uuid"
)

// ID filters vertices based on their ID field.
func ID(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id uuid.UUID) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// HclID applies equality check predicate on the "hcl_id" field. It's identical to HclIDEQ.
func HclID(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldName), v))
	})
}

// Description applies equality check predicate on the "description" field. It's identical to DescriptionEQ.
func Description(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDescription), v))
	})
}

// Program applies equality check predicate on the "program" field. It's identical to ProgramEQ.
func Program(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldProgram), v))
	})
}

// IgnoreErrors applies equality check predicate on the "ignore_errors" field. It's identical to IgnoreErrorsEQ.
func IgnoreErrors(v bool) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIgnoreErrors), v))
	})
}

// Disabled applies equality check predicate on the "disabled" field. It's identical to DisabledEQ.
func Disabled(v bool) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDisabled), v))
	})
}

// Cooldown applies equality check predicate on the "cooldown" field. It's identical to CooldownEQ.
func Cooldown(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCooldown), v))
	})
}

// Timeout applies equality check predicate on the "timeout" field. It's identical to TimeoutEQ.
func Timeout(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldTimeout), v))
	})
}

// HclIDEQ applies the EQ predicate on the "hcl_id" field.
func HclIDEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// HclIDNEQ applies the NEQ predicate on the "hcl_id" field.
func HclIDNEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldHclID), v))
	})
}

// HclIDIn applies the In predicate on the "hcl_id" field.
func HclIDIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldHclID), v...))
	})
}

// HclIDNotIn applies the NotIn predicate on the "hcl_id" field.
func HclIDNotIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldHclID), v...))
	})
}

// HclIDGT applies the GT predicate on the "hcl_id" field.
func HclIDGT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldHclID), v))
	})
}

// HclIDGTE applies the GTE predicate on the "hcl_id" field.
func HclIDGTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldHclID), v))
	})
}

// HclIDLT applies the LT predicate on the "hcl_id" field.
func HclIDLT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldHclID), v))
	})
}

// HclIDLTE applies the LTE predicate on the "hcl_id" field.
func HclIDLTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldHclID), v))
	})
}

// HclIDContains applies the Contains predicate on the "hcl_id" field.
func HclIDContains(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldHclID), v))
	})
}

// HclIDHasPrefix applies the HasPrefix predicate on the "hcl_id" field.
func HclIDHasPrefix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldHclID), v))
	})
}

// HclIDHasSuffix applies the HasSuffix predicate on the "hcl_id" field.
func HclIDHasSuffix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldHclID), v))
	})
}

// HclIDEqualFold applies the EqualFold predicate on the "hcl_id" field.
func HclIDEqualFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldHclID), v))
	})
}

// HclIDContainsFold applies the ContainsFold predicate on the "hcl_id" field.
func HclIDContainsFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldHclID), v))
	})
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldName), v))
	})
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldName), v))
	})
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldName), v...))
	})
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldName), v...))
	})
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldName), v))
	})
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldName), v))
	})
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldName), v))
	})
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldName), v))
	})
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldName), v))
	})
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldName), v))
	})
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldName), v))
	})
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldName), v))
	})
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldName), v))
	})
}

// DescriptionEQ applies the EQ predicate on the "description" field.
func DescriptionEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDescription), v))
	})
}

// DescriptionNEQ applies the NEQ predicate on the "description" field.
func DescriptionNEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDescription), v))
	})
}

// DescriptionIn applies the In predicate on the "description" field.
func DescriptionIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldDescription), v...))
	})
}

// DescriptionNotIn applies the NotIn predicate on the "description" field.
func DescriptionNotIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldDescription), v...))
	})
}

// DescriptionGT applies the GT predicate on the "description" field.
func DescriptionGT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldDescription), v))
	})
}

// DescriptionGTE applies the GTE predicate on the "description" field.
func DescriptionGTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldDescription), v))
	})
}

// DescriptionLT applies the LT predicate on the "description" field.
func DescriptionLT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldDescription), v))
	})
}

// DescriptionLTE applies the LTE predicate on the "description" field.
func DescriptionLTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldDescription), v))
	})
}

// DescriptionContains applies the Contains predicate on the "description" field.
func DescriptionContains(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldDescription), v))
	})
}

// DescriptionHasPrefix applies the HasPrefix predicate on the "description" field.
func DescriptionHasPrefix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldDescription), v))
	})
}

// DescriptionHasSuffix applies the HasSuffix predicate on the "description" field.
func DescriptionHasSuffix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldDescription), v))
	})
}

// DescriptionEqualFold applies the EqualFold predicate on the "description" field.
func DescriptionEqualFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldDescription), v))
	})
}

// DescriptionContainsFold applies the ContainsFold predicate on the "description" field.
func DescriptionContainsFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldDescription), v))
	})
}

// ProgramEQ applies the EQ predicate on the "program" field.
func ProgramEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldProgram), v))
	})
}

// ProgramNEQ applies the NEQ predicate on the "program" field.
func ProgramNEQ(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldProgram), v))
	})
}

// ProgramIn applies the In predicate on the "program" field.
func ProgramIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldProgram), v...))
	})
}

// ProgramNotIn applies the NotIn predicate on the "program" field.
func ProgramNotIn(vs ...string) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldProgram), v...))
	})
}

// ProgramGT applies the GT predicate on the "program" field.
func ProgramGT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldProgram), v))
	})
}

// ProgramGTE applies the GTE predicate on the "program" field.
func ProgramGTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldProgram), v))
	})
}

// ProgramLT applies the LT predicate on the "program" field.
func ProgramLT(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldProgram), v))
	})
}

// ProgramLTE applies the LTE predicate on the "program" field.
func ProgramLTE(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldProgram), v))
	})
}

// ProgramContains applies the Contains predicate on the "program" field.
func ProgramContains(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldProgram), v))
	})
}

// ProgramHasPrefix applies the HasPrefix predicate on the "program" field.
func ProgramHasPrefix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldProgram), v))
	})
}

// ProgramHasSuffix applies the HasSuffix predicate on the "program" field.
func ProgramHasSuffix(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldProgram), v))
	})
}

// ProgramEqualFold applies the EqualFold predicate on the "program" field.
func ProgramEqualFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldProgram), v))
	})
}

// ProgramContainsFold applies the ContainsFold predicate on the "program" field.
func ProgramContainsFold(v string) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldProgram), v))
	})
}

// IgnoreErrorsEQ applies the EQ predicate on the "ignore_errors" field.
func IgnoreErrorsEQ(v bool) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIgnoreErrors), v))
	})
}

// IgnoreErrorsNEQ applies the NEQ predicate on the "ignore_errors" field.
func IgnoreErrorsNEQ(v bool) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldIgnoreErrors), v))
	})
}

// DisabledEQ applies the EQ predicate on the "disabled" field.
func DisabledEQ(v bool) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDisabled), v))
	})
}

// DisabledNEQ applies the NEQ predicate on the "disabled" field.
func DisabledNEQ(v bool) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDisabled), v))
	})
}

// CooldownEQ applies the EQ predicate on the "cooldown" field.
func CooldownEQ(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCooldown), v))
	})
}

// CooldownNEQ applies the NEQ predicate on the "cooldown" field.
func CooldownNEQ(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldCooldown), v))
	})
}

// CooldownIn applies the In predicate on the "cooldown" field.
func CooldownIn(vs ...int) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldCooldown), v...))
	})
}

// CooldownNotIn applies the NotIn predicate on the "cooldown" field.
func CooldownNotIn(vs ...int) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldCooldown), v...))
	})
}

// CooldownGT applies the GT predicate on the "cooldown" field.
func CooldownGT(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldCooldown), v))
	})
}

// CooldownGTE applies the GTE predicate on the "cooldown" field.
func CooldownGTE(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldCooldown), v))
	})
}

// CooldownLT applies the LT predicate on the "cooldown" field.
func CooldownLT(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldCooldown), v))
	})
}

// CooldownLTE applies the LTE predicate on the "cooldown" field.
func CooldownLTE(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldCooldown), v))
	})
}

// TimeoutEQ applies the EQ predicate on the "timeout" field.
func TimeoutEQ(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldTimeout), v))
	})
}

// TimeoutNEQ applies the NEQ predicate on the "timeout" field.
func TimeoutNEQ(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldTimeout), v))
	})
}

// TimeoutIn applies the In predicate on the "timeout" field.
func TimeoutIn(vs ...int) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldTimeout), v...))
	})
}

// TimeoutNotIn applies the NotIn predicate on the "timeout" field.
func TimeoutNotIn(vs ...int) predicate.Command {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldTimeout), v...))
	})
}

// TimeoutGT applies the GT predicate on the "timeout" field.
func TimeoutGT(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldTimeout), v))
	})
}

// TimeoutGTE applies the GTE predicate on the "timeout" field.
func TimeoutGTE(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldTimeout), v))
	})
}

// TimeoutLT applies the LT predicate on the "timeout" field.
func TimeoutLT(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldTimeout), v))
	})
}

// TimeoutLTE applies the LTE predicate on the "timeout" field.
func TimeoutLTE(v int) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldTimeout), v))
	})
}

// HasCommandToUser applies the HasEdge predicate on the "CommandToUser" edge.
func HasCommandToUser() predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CommandToUserTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, CommandToUserTable, CommandToUserColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCommandToUserWith applies the HasEdge predicate on the "CommandToUser" edge with a given conditions (other predicates).
func HasCommandToUserWith(preds ...predicate.User) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CommandToUserInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, CommandToUserTable, CommandToUserColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasCommandToEnvironment applies the HasEdge predicate on the "CommandToEnvironment" edge.
func HasCommandToEnvironment() predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CommandToEnvironmentTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, CommandToEnvironmentTable, CommandToEnvironmentColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCommandToEnvironmentWith applies the HasEdge predicate on the "CommandToEnvironment" edge with a given conditions (other predicates).
func HasCommandToEnvironmentWith(preds ...predicate.Environment) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CommandToEnvironmentInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, CommandToEnvironmentTable, CommandToEnvironmentColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Command) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Command) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Command) predicate.Command {
	return predicate.Command(func(s *sql.Selector) {
		p(s.Not())
	})
}
