// Code generated by entc, DO NOT EDIT.

package network

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/gen0cide/laforge/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
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
func IDNotIn(ids ...int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
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
func IDGT(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// HclID applies equality check predicate on the "hcl_id" field. It's identical to HclIDEQ.
func HclID(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldName), v))
	})
}

// Cidr applies equality check predicate on the "cidr" field. It's identical to CidrEQ.
func Cidr(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCidr), v))
	})
}

// VdiVisible applies equality check predicate on the "vdi_visible" field. It's identical to VdiVisibleEQ.
func VdiVisible(v bool) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldVdiVisible), v))
	})
}

// HclIDEQ applies the EQ predicate on the "hcl_id" field.
func HclIDEQ(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// HclIDNEQ applies the NEQ predicate on the "hcl_id" field.
func HclIDNEQ(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldHclID), v))
	})
}

// HclIDIn applies the In predicate on the "hcl_id" field.
func HclIDIn(vs ...string) predicate.Network {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Network(func(s *sql.Selector) {
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
func HclIDNotIn(vs ...string) predicate.Network {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Network(func(s *sql.Selector) {
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
func HclIDGT(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldHclID), v))
	})
}

// HclIDGTE applies the GTE predicate on the "hcl_id" field.
func HclIDGTE(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldHclID), v))
	})
}

// HclIDLT applies the LT predicate on the "hcl_id" field.
func HclIDLT(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldHclID), v))
	})
}

// HclIDLTE applies the LTE predicate on the "hcl_id" field.
func HclIDLTE(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldHclID), v))
	})
}

// HclIDContains applies the Contains predicate on the "hcl_id" field.
func HclIDContains(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldHclID), v))
	})
}

// HclIDHasPrefix applies the HasPrefix predicate on the "hcl_id" field.
func HclIDHasPrefix(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldHclID), v))
	})
}

// HclIDHasSuffix applies the HasSuffix predicate on the "hcl_id" field.
func HclIDHasSuffix(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldHclID), v))
	})
}

// HclIDEqualFold applies the EqualFold predicate on the "hcl_id" field.
func HclIDEqualFold(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldHclID), v))
	})
}

// HclIDContainsFold applies the ContainsFold predicate on the "hcl_id" field.
func HclIDContainsFold(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldHclID), v))
	})
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldName), v))
	})
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldName), v))
	})
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.Network {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Network(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldName), v...))
	})
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.Network {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Network(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldName), v...))
	})
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldName), v))
	})
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldName), v))
	})
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldName), v))
	})
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldName), v))
	})
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldName), v))
	})
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldName), v))
	})
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldName), v))
	})
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldName), v))
	})
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldName), v))
	})
}

// CidrEQ applies the EQ predicate on the "cidr" field.
func CidrEQ(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCidr), v))
	})
}

// CidrNEQ applies the NEQ predicate on the "cidr" field.
func CidrNEQ(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldCidr), v))
	})
}

// CidrIn applies the In predicate on the "cidr" field.
func CidrIn(vs ...string) predicate.Network {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Network(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldCidr), v...))
	})
}

// CidrNotIn applies the NotIn predicate on the "cidr" field.
func CidrNotIn(vs ...string) predicate.Network {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Network(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldCidr), v...))
	})
}

// CidrGT applies the GT predicate on the "cidr" field.
func CidrGT(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldCidr), v))
	})
}

// CidrGTE applies the GTE predicate on the "cidr" field.
func CidrGTE(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldCidr), v))
	})
}

// CidrLT applies the LT predicate on the "cidr" field.
func CidrLT(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldCidr), v))
	})
}

// CidrLTE applies the LTE predicate on the "cidr" field.
func CidrLTE(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldCidr), v))
	})
}

// CidrContains applies the Contains predicate on the "cidr" field.
func CidrContains(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldCidr), v))
	})
}

// CidrHasPrefix applies the HasPrefix predicate on the "cidr" field.
func CidrHasPrefix(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldCidr), v))
	})
}

// CidrHasSuffix applies the HasSuffix predicate on the "cidr" field.
func CidrHasSuffix(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldCidr), v))
	})
}

// CidrEqualFold applies the EqualFold predicate on the "cidr" field.
func CidrEqualFold(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldCidr), v))
	})
}

// CidrContainsFold applies the ContainsFold predicate on the "cidr" field.
func CidrContainsFold(v string) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldCidr), v))
	})
}

// VdiVisibleEQ applies the EQ predicate on the "vdi_visible" field.
func VdiVisibleEQ(v bool) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldVdiVisible), v))
	})
}

// VdiVisibleNEQ applies the NEQ predicate on the "vdi_visible" field.
func VdiVisibleNEQ(v bool) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldVdiVisible), v))
	})
}

// HasNetworkToEnvironment applies the HasEdge predicate on the "NetworkToEnvironment" edge.
func HasNetworkToEnvironment() predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(NetworkToEnvironmentTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, NetworkToEnvironmentTable, NetworkToEnvironmentColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasNetworkToEnvironmentWith applies the HasEdge predicate on the "NetworkToEnvironment" edge with a given conditions (other predicates).
func HasNetworkToEnvironmentWith(preds ...predicate.Environment) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(NetworkToEnvironmentInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, NetworkToEnvironmentTable, NetworkToEnvironmentColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasNetworkToHostDependency applies the HasEdge predicate on the "NetworkToHostDependency" edge.
func HasNetworkToHostDependency() predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(NetworkToHostDependencyTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, NetworkToHostDependencyTable, NetworkToHostDependencyColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasNetworkToHostDependencyWith applies the HasEdge predicate on the "NetworkToHostDependency" edge with a given conditions (other predicates).
func HasNetworkToHostDependencyWith(preds ...predicate.HostDependency) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(NetworkToHostDependencyInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, NetworkToHostDependencyTable, NetworkToHostDependencyColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasNetworkToIncludedNetwork applies the HasEdge predicate on the "NetworkToIncludedNetwork" edge.
func HasNetworkToIncludedNetwork() predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(NetworkToIncludedNetworkTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, NetworkToIncludedNetworkTable, NetworkToIncludedNetworkPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasNetworkToIncludedNetworkWith applies the HasEdge predicate on the "NetworkToIncludedNetwork" edge with a given conditions (other predicates).
func HasNetworkToIncludedNetworkWith(preds ...predicate.IncludedNetwork) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(NetworkToIncludedNetworkInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, NetworkToIncludedNetworkTable, NetworkToIncludedNetworkPrimaryKey...),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Network) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Network) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
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
func Not(p predicate.Network) predicate.Network {
	return predicate.Network(func(s *sql.Selector) {
		p(s.Not())
	})
}
