// Code generated by entc, DO NOT EDIT.

package competition

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/gen0cide/laforge/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
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
func IDNotIn(ids ...int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
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
func IDGT(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// HclID applies equality check predicate on the "hcl_id" field. It's identical to HclIDEQ.
func HclID(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// RootPassword applies equality check predicate on the "root_password" field. It's identical to RootPasswordEQ.
func RootPassword(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldRootPassword), v))
	})
}

// HclIDEQ applies the EQ predicate on the "hcl_id" field.
func HclIDEQ(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// HclIDNEQ applies the NEQ predicate on the "hcl_id" field.
func HclIDNEQ(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldHclID), v))
	})
}

// HclIDIn applies the In predicate on the "hcl_id" field.
func HclIDIn(vs ...string) predicate.Competition {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Competition(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldHclID), v...))
	})
}

// HclIDNotIn applies the NotIn predicate on the "hcl_id" field.
func HclIDNotIn(vs ...string) predicate.Competition {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Competition(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldHclID), v...))
	})
}

// HclIDGT applies the GT predicate on the "hcl_id" field.
func HclIDGT(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldHclID), v))
	})
}

// HclIDGTE applies the GTE predicate on the "hcl_id" field.
func HclIDGTE(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldHclID), v))
	})
}

// HclIDLT applies the LT predicate on the "hcl_id" field.
func HclIDLT(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldHclID), v))
	})
}

// HclIDLTE applies the LTE predicate on the "hcl_id" field.
func HclIDLTE(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldHclID), v))
	})
}

// HclIDContains applies the Contains predicate on the "hcl_id" field.
func HclIDContains(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldHclID), v))
	})
}

// HclIDHasPrefix applies the HasPrefix predicate on the "hcl_id" field.
func HclIDHasPrefix(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldHclID), v))
	})
}

// HclIDHasSuffix applies the HasSuffix predicate on the "hcl_id" field.
func HclIDHasSuffix(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldHclID), v))
	})
}

// HclIDEqualFold applies the EqualFold predicate on the "hcl_id" field.
func HclIDEqualFold(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldHclID), v))
	})
}

// HclIDContainsFold applies the ContainsFold predicate on the "hcl_id" field.
func HclIDContainsFold(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldHclID), v))
	})
}

// RootPasswordEQ applies the EQ predicate on the "root_password" field.
func RootPasswordEQ(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldRootPassword), v))
	})
}

// RootPasswordNEQ applies the NEQ predicate on the "root_password" field.
func RootPasswordNEQ(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldRootPassword), v))
	})
}

// RootPasswordIn applies the In predicate on the "root_password" field.
func RootPasswordIn(vs ...string) predicate.Competition {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Competition(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldRootPassword), v...))
	})
}

// RootPasswordNotIn applies the NotIn predicate on the "root_password" field.
func RootPasswordNotIn(vs ...string) predicate.Competition {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Competition(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldRootPassword), v...))
	})
}

// RootPasswordGT applies the GT predicate on the "root_password" field.
func RootPasswordGT(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldRootPassword), v))
	})
}

// RootPasswordGTE applies the GTE predicate on the "root_password" field.
func RootPasswordGTE(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldRootPassword), v))
	})
}

// RootPasswordLT applies the LT predicate on the "root_password" field.
func RootPasswordLT(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldRootPassword), v))
	})
}

// RootPasswordLTE applies the LTE predicate on the "root_password" field.
func RootPasswordLTE(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldRootPassword), v))
	})
}

// RootPasswordContains applies the Contains predicate on the "root_password" field.
func RootPasswordContains(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldRootPassword), v))
	})
}

// RootPasswordHasPrefix applies the HasPrefix predicate on the "root_password" field.
func RootPasswordHasPrefix(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldRootPassword), v))
	})
}

// RootPasswordHasSuffix applies the HasSuffix predicate on the "root_password" field.
func RootPasswordHasSuffix(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldRootPassword), v))
	})
}

// RootPasswordEqualFold applies the EqualFold predicate on the "root_password" field.
func RootPasswordEqualFold(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldRootPassword), v))
	})
}

// RootPasswordContainsFold applies the ContainsFold predicate on the "root_password" field.
func RootPasswordContainsFold(v string) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldRootPassword), v))
	})
}

// HasCompetitionToDNS applies the HasEdge predicate on the "CompetitionToDNS" edge.
func HasCompetitionToDNS() predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CompetitionToDNSTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, CompetitionToDNSTable, CompetitionToDNSPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCompetitionToDNSWith applies the HasEdge predicate on the "CompetitionToDNS" edge with a given conditions (other predicates).
func HasCompetitionToDNSWith(preds ...predicate.DNS) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CompetitionToDNSInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, CompetitionToDNSTable, CompetitionToDNSPrimaryKey...),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasCompetitionToEnvironment applies the HasEdge predicate on the "CompetitionToEnvironment" edge.
func HasCompetitionToEnvironment() predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CompetitionToEnvironmentTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, CompetitionToEnvironmentTable, CompetitionToEnvironmentColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCompetitionToEnvironmentWith applies the HasEdge predicate on the "CompetitionToEnvironment" edge with a given conditions (other predicates).
func HasCompetitionToEnvironmentWith(preds ...predicate.Environment) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CompetitionToEnvironmentInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, CompetitionToEnvironmentTable, CompetitionToEnvironmentColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasCompetitionToBuild applies the HasEdge predicate on the "CompetitionToBuild" edge.
func HasCompetitionToBuild() predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CompetitionToBuildTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, CompetitionToBuildTable, CompetitionToBuildColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasCompetitionToBuildWith applies the HasEdge predicate on the "CompetitionToBuild" edge with a given conditions (other predicates).
func HasCompetitionToBuildWith(preds ...predicate.Build) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(CompetitionToBuildInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, CompetitionToBuildTable, CompetitionToBuildColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Competition) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Competition) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
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
func Not(p predicate.Competition) predicate.Competition {
	return predicate.Competition(func(s *sql.Selector) {
		p(s.Not())
	})
}
