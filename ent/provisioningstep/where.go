// Code generated by entc, DO NOT EDIT.

package provisioningstep

import (
	"github.com/facebook/ent/dialect/sql"
	"github.com/facebook/ent/dialect/sql/sqlgraph"
	"github.com/gen0cide/laforge/ent/predicate"
)

// ID filters vertices based on their identifier.
func ID(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(ids) == 0 {
			s.Where(sql.False())
			return
		}
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(ids) == 0 {
			s.Where(sql.False())
			return
		}
		v := make([]interface{}, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// ProvisionerType applies equality check predicate on the "provisioner_type" field. It's identical to ProvisionerTypeEQ.
func ProvisionerType(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldProvisionerType), v))
	})
}

// StepNumber applies equality check predicate on the "step_number" field. It's identical to StepNumberEQ.
func StepNumber(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldStepNumber), v))
	})
}

// ProvisionerTypeEQ applies the EQ predicate on the "provisioner_type" field.
func ProvisionerTypeEQ(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeNEQ applies the NEQ predicate on the "provisioner_type" field.
func ProvisionerTypeNEQ(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeIn applies the In predicate on the "provisioner_type" field.
func ProvisionerTypeIn(vs ...string) predicate.ProvisioningStep {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldProvisionerType), v...))
	})
}

// ProvisionerTypeNotIn applies the NotIn predicate on the "provisioner_type" field.
func ProvisionerTypeNotIn(vs ...string) predicate.ProvisioningStep {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldProvisionerType), v...))
	})
}

// ProvisionerTypeGT applies the GT predicate on the "provisioner_type" field.
func ProvisionerTypeGT(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeGTE applies the GTE predicate on the "provisioner_type" field.
func ProvisionerTypeGTE(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeLT applies the LT predicate on the "provisioner_type" field.
func ProvisionerTypeLT(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeLTE applies the LTE predicate on the "provisioner_type" field.
func ProvisionerTypeLTE(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeContains applies the Contains predicate on the "provisioner_type" field.
func ProvisionerTypeContains(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeHasPrefix applies the HasPrefix predicate on the "provisioner_type" field.
func ProvisionerTypeHasPrefix(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeHasSuffix applies the HasSuffix predicate on the "provisioner_type" field.
func ProvisionerTypeHasSuffix(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeEqualFold applies the EqualFold predicate on the "provisioner_type" field.
func ProvisionerTypeEqualFold(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldProvisionerType), v))
	})
}

// ProvisionerTypeContainsFold applies the ContainsFold predicate on the "provisioner_type" field.
func ProvisionerTypeContainsFold(v string) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldProvisionerType), v))
	})
}

// StepNumberEQ applies the EQ predicate on the "step_number" field.
func StepNumberEQ(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldStepNumber), v))
	})
}

// StepNumberNEQ applies the NEQ predicate on the "step_number" field.
func StepNumberNEQ(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldStepNumber), v))
	})
}

// StepNumberIn applies the In predicate on the "step_number" field.
func StepNumberIn(vs ...int) predicate.ProvisioningStep {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldStepNumber), v...))
	})
}

// StepNumberNotIn applies the NotIn predicate on the "step_number" field.
func StepNumberNotIn(vs ...int) predicate.ProvisioningStep {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldStepNumber), v...))
	})
}

// StepNumberGT applies the GT predicate on the "step_number" field.
func StepNumberGT(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldStepNumber), v))
	})
}

// StepNumberGTE applies the GTE predicate on the "step_number" field.
func StepNumberGTE(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldStepNumber), v))
	})
}

// StepNumberLT applies the LT predicate on the "step_number" field.
func StepNumberLT(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldStepNumber), v))
	})
}

// StepNumberLTE applies the LTE predicate on the "step_number" field.
func StepNumberLTE(v int) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldStepNumber), v))
	})
}

// HasStatus applies the HasEdge predicate on the "status" edge.
func HasStatus() predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(StatusTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, StatusTable, StatusColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasStatusWith applies the HasEdge predicate on the "status" edge with a given conditions (other predicates).
func HasStatusWith(preds ...predicate.Status) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(StatusInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, StatusTable, StatusColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasProvisionedHost applies the HasEdge predicate on the "provisioned_host" edge.
func HasProvisionedHost() predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ProvisionedHostTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, ProvisionedHostTable, ProvisionedHostPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasProvisionedHostWith applies the HasEdge predicate on the "provisioned_host" edge with a given conditions (other predicates).
func HasProvisionedHostWith(preds ...predicate.ProvisionedHost) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ProvisionedHostInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, ProvisionedHostTable, ProvisionedHostPrimaryKey...),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasScript applies the HasEdge predicate on the "script" edge.
func HasScript() predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ScriptTable, ScriptColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasScriptWith applies the HasEdge predicate on the "script" edge with a given conditions (other predicates).
func HasScriptWith(preds ...predicate.Script) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ScriptTable, ScriptColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasCommand applies the HasEdge predicate on the "command" edge.
func HasCommand() predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CommandTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, CommandTable, CommandColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCommandWith applies the HasEdge predicate on the "command" edge with a given conditions (other predicates).
func HasCommandWith(preds ...predicate.Command) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CommandInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, CommandTable, CommandColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasDNSRecord applies the HasEdge predicate on the "dns_record" edge.
func HasDNSRecord() predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(DNSRecordTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, DNSRecordTable, DNSRecordColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasDNSRecordWith applies the HasEdge predicate on the "dns_record" edge with a given conditions (other predicates).
func HasDNSRecordWith(preds ...predicate.DNSRecord) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(DNSRecordInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, DNSRecordTable, DNSRecordColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasRemoteFile applies the HasEdge predicate on the "remote_file" edge.
func HasRemoteFile() predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(RemoteFileTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, RemoteFileTable, RemoteFileColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasRemoteFileWith applies the HasEdge predicate on the "remote_file" edge with a given conditions (other predicates).
func HasRemoteFileWith(preds ...predicate.RemoteFile) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(RemoteFileInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, RemoteFileTable, RemoteFileColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups list of predicates with the AND operator between them.
func And(predicates ...predicate.ProvisioningStep) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups list of predicates with the OR operator between them.
func Or(predicates ...predicate.ProvisioningStep) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
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
func Not(p predicate.ProvisioningStep) predicate.ProvisioningStep {
	return predicate.ProvisioningStep(func(s *sql.Selector) {
		p(s.Not())
	})
}
