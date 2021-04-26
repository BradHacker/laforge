// Code generated by entc, DO NOT EDIT.

package host

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/gen0cide/laforge/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
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
func IDNotIn(ids ...int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
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
func IDGT(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// HclID applies equality check predicate on the "hcl_id" field. It's identical to HclIDEQ.
func HclID(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// Hostname applies equality check predicate on the "hostname" field. It's identical to HostnameEQ.
func Hostname(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHostname), v))
	})
}

// Description applies equality check predicate on the "description" field. It's identical to DescriptionEQ.
func Description(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDescription), v))
	})
}

// OS applies equality check predicate on the "OS" field. It's identical to OSEQ.
func OS(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOS), v))
	})
}

// LastOctet applies equality check predicate on the "last_octet" field. It's identical to LastOctetEQ.
func LastOctet(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldLastOctet), v))
	})
}

// InstanceSize applies equality check predicate on the "instance_size" field. It's identical to InstanceSizeEQ.
func InstanceSize(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldInstanceSize), v))
	})
}

// AllowMACChanges applies equality check predicate on the "allow_mac_changes" field. It's identical to AllowMACChangesEQ.
func AllowMACChanges(v bool) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldAllowMACChanges), v))
	})
}

// OverridePassword applies equality check predicate on the "override_password" field. It's identical to OverridePasswordEQ.
func OverridePassword(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOverridePassword), v))
	})
}

// HclIDEQ applies the EQ predicate on the "hcl_id" field.
func HclIDEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// HclIDNEQ applies the NEQ predicate on the "hcl_id" field.
func HclIDNEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldHclID), v))
	})
}

// HclIDIn applies the In predicate on the "hcl_id" field.
func HclIDIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
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
func HclIDNotIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
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
func HclIDGT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldHclID), v))
	})
}

// HclIDGTE applies the GTE predicate on the "hcl_id" field.
func HclIDGTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldHclID), v))
	})
}

// HclIDLT applies the LT predicate on the "hcl_id" field.
func HclIDLT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldHclID), v))
	})
}

// HclIDLTE applies the LTE predicate on the "hcl_id" field.
func HclIDLTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldHclID), v))
	})
}

// HclIDContains applies the Contains predicate on the "hcl_id" field.
func HclIDContains(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldHclID), v))
	})
}

// HclIDHasPrefix applies the HasPrefix predicate on the "hcl_id" field.
func HclIDHasPrefix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldHclID), v))
	})
}

// HclIDHasSuffix applies the HasSuffix predicate on the "hcl_id" field.
func HclIDHasSuffix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldHclID), v))
	})
}

// HclIDEqualFold applies the EqualFold predicate on the "hcl_id" field.
func HclIDEqualFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldHclID), v))
	})
}

// HclIDContainsFold applies the ContainsFold predicate on the "hcl_id" field.
func HclIDContainsFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldHclID), v))
	})
}

// HostnameEQ applies the EQ predicate on the "hostname" field.
func HostnameEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHostname), v))
	})
}

// HostnameNEQ applies the NEQ predicate on the "hostname" field.
func HostnameNEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldHostname), v))
	})
}

// HostnameIn applies the In predicate on the "hostname" field.
func HostnameIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldHostname), v...))
	})
}

// HostnameNotIn applies the NotIn predicate on the "hostname" field.
func HostnameNotIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldHostname), v...))
	})
}

// HostnameGT applies the GT predicate on the "hostname" field.
func HostnameGT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldHostname), v))
	})
}

// HostnameGTE applies the GTE predicate on the "hostname" field.
func HostnameGTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldHostname), v))
	})
}

// HostnameLT applies the LT predicate on the "hostname" field.
func HostnameLT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldHostname), v))
	})
}

// HostnameLTE applies the LTE predicate on the "hostname" field.
func HostnameLTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldHostname), v))
	})
}

// HostnameContains applies the Contains predicate on the "hostname" field.
func HostnameContains(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldHostname), v))
	})
}

// HostnameHasPrefix applies the HasPrefix predicate on the "hostname" field.
func HostnameHasPrefix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldHostname), v))
	})
}

// HostnameHasSuffix applies the HasSuffix predicate on the "hostname" field.
func HostnameHasSuffix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldHostname), v))
	})
}

// HostnameEqualFold applies the EqualFold predicate on the "hostname" field.
func HostnameEqualFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldHostname), v))
	})
}

// HostnameContainsFold applies the ContainsFold predicate on the "hostname" field.
func HostnameContainsFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldHostname), v))
	})
}

// DescriptionEQ applies the EQ predicate on the "description" field.
func DescriptionEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDescription), v))
	})
}

// DescriptionNEQ applies the NEQ predicate on the "description" field.
func DescriptionNEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDescription), v))
	})
}

// DescriptionIn applies the In predicate on the "description" field.
func DescriptionIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldDescription), v...))
	})
}

// DescriptionNotIn applies the NotIn predicate on the "description" field.
func DescriptionNotIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldDescription), v...))
	})
}

// DescriptionGT applies the GT predicate on the "description" field.
func DescriptionGT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldDescription), v))
	})
}

// DescriptionGTE applies the GTE predicate on the "description" field.
func DescriptionGTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldDescription), v))
	})
}

// DescriptionLT applies the LT predicate on the "description" field.
func DescriptionLT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldDescription), v))
	})
}

// DescriptionLTE applies the LTE predicate on the "description" field.
func DescriptionLTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldDescription), v))
	})
}

// DescriptionContains applies the Contains predicate on the "description" field.
func DescriptionContains(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldDescription), v))
	})
}

// DescriptionHasPrefix applies the HasPrefix predicate on the "description" field.
func DescriptionHasPrefix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldDescription), v))
	})
}

// DescriptionHasSuffix applies the HasSuffix predicate on the "description" field.
func DescriptionHasSuffix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldDescription), v))
	})
}

// DescriptionEqualFold applies the EqualFold predicate on the "description" field.
func DescriptionEqualFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldDescription), v))
	})
}

// DescriptionContainsFold applies the ContainsFold predicate on the "description" field.
func DescriptionContainsFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldDescription), v))
	})
}

// OSEQ applies the EQ predicate on the "OS" field.
func OSEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOS), v))
	})
}

// OSNEQ applies the NEQ predicate on the "OS" field.
func OSNEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldOS), v))
	})
}

// OSIn applies the In predicate on the "OS" field.
func OSIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldOS), v...))
	})
}

// OSNotIn applies the NotIn predicate on the "OS" field.
func OSNotIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldOS), v...))
	})
}

// OSGT applies the GT predicate on the "OS" field.
func OSGT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldOS), v))
	})
}

// OSGTE applies the GTE predicate on the "OS" field.
func OSGTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldOS), v))
	})
}

// OSLT applies the LT predicate on the "OS" field.
func OSLT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldOS), v))
	})
}

// OSLTE applies the LTE predicate on the "OS" field.
func OSLTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldOS), v))
	})
}

// OSContains applies the Contains predicate on the "OS" field.
func OSContains(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldOS), v))
	})
}

// OSHasPrefix applies the HasPrefix predicate on the "OS" field.
func OSHasPrefix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldOS), v))
	})
}

// OSHasSuffix applies the HasSuffix predicate on the "OS" field.
func OSHasSuffix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldOS), v))
	})
}

// OSEqualFold applies the EqualFold predicate on the "OS" field.
func OSEqualFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldOS), v))
	})
}

// OSContainsFold applies the ContainsFold predicate on the "OS" field.
func OSContainsFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldOS), v))
	})
}

// LastOctetEQ applies the EQ predicate on the "last_octet" field.
func LastOctetEQ(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldLastOctet), v))
	})
}

// LastOctetNEQ applies the NEQ predicate on the "last_octet" field.
func LastOctetNEQ(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldLastOctet), v))
	})
}

// LastOctetIn applies the In predicate on the "last_octet" field.
func LastOctetIn(vs ...int) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldLastOctet), v...))
	})
}

// LastOctetNotIn applies the NotIn predicate on the "last_octet" field.
func LastOctetNotIn(vs ...int) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldLastOctet), v...))
	})
}

// LastOctetGT applies the GT predicate on the "last_octet" field.
func LastOctetGT(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldLastOctet), v))
	})
}

// LastOctetGTE applies the GTE predicate on the "last_octet" field.
func LastOctetGTE(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldLastOctet), v))
	})
}

// LastOctetLT applies the LT predicate on the "last_octet" field.
func LastOctetLT(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldLastOctet), v))
	})
}

// LastOctetLTE applies the LTE predicate on the "last_octet" field.
func LastOctetLTE(v int) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldLastOctet), v))
	})
}

// InstanceSizeEQ applies the EQ predicate on the "instance_size" field.
func InstanceSizeEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeNEQ applies the NEQ predicate on the "instance_size" field.
func InstanceSizeNEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeIn applies the In predicate on the "instance_size" field.
func InstanceSizeIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldInstanceSize), v...))
	})
}

// InstanceSizeNotIn applies the NotIn predicate on the "instance_size" field.
func InstanceSizeNotIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldInstanceSize), v...))
	})
}

// InstanceSizeGT applies the GT predicate on the "instance_size" field.
func InstanceSizeGT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeGTE applies the GTE predicate on the "instance_size" field.
func InstanceSizeGTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeLT applies the LT predicate on the "instance_size" field.
func InstanceSizeLT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeLTE applies the LTE predicate on the "instance_size" field.
func InstanceSizeLTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeContains applies the Contains predicate on the "instance_size" field.
func InstanceSizeContains(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeHasPrefix applies the HasPrefix predicate on the "instance_size" field.
func InstanceSizeHasPrefix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeHasSuffix applies the HasSuffix predicate on the "instance_size" field.
func InstanceSizeHasSuffix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeEqualFold applies the EqualFold predicate on the "instance_size" field.
func InstanceSizeEqualFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldInstanceSize), v))
	})
}

// InstanceSizeContainsFold applies the ContainsFold predicate on the "instance_size" field.
func InstanceSizeContainsFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldInstanceSize), v))
	})
}

// AllowMACChangesEQ applies the EQ predicate on the "allow_mac_changes" field.
func AllowMACChangesEQ(v bool) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldAllowMACChanges), v))
	})
}

// AllowMACChangesNEQ applies the NEQ predicate on the "allow_mac_changes" field.
func AllowMACChangesNEQ(v bool) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldAllowMACChanges), v))
	})
}

// OverridePasswordEQ applies the EQ predicate on the "override_password" field.
func OverridePasswordEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordNEQ applies the NEQ predicate on the "override_password" field.
func OverridePasswordNEQ(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordIn applies the In predicate on the "override_password" field.
func OverridePasswordIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldOverridePassword), v...))
	})
}

// OverridePasswordNotIn applies the NotIn predicate on the "override_password" field.
func OverridePasswordNotIn(vs ...string) predicate.Host {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Host(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldOverridePassword), v...))
	})
}

// OverridePasswordGT applies the GT predicate on the "override_password" field.
func OverridePasswordGT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordGTE applies the GTE predicate on the "override_password" field.
func OverridePasswordGTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordLT applies the LT predicate on the "override_password" field.
func OverridePasswordLT(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordLTE applies the LTE predicate on the "override_password" field.
func OverridePasswordLTE(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordContains applies the Contains predicate on the "override_password" field.
func OverridePasswordContains(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordHasPrefix applies the HasPrefix predicate on the "override_password" field.
func OverridePasswordHasPrefix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordHasSuffix applies the HasSuffix predicate on the "override_password" field.
func OverridePasswordHasSuffix(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordEqualFold applies the EqualFold predicate on the "override_password" field.
func OverridePasswordEqualFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldOverridePassword), v))
	})
}

// OverridePasswordContainsFold applies the ContainsFold predicate on the "override_password" field.
func OverridePasswordContainsFold(v string) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldOverridePassword), v))
	})
}

// ProvisionStepsIsNil applies the IsNil predicate on the "provision_steps" field.
func ProvisionStepsIsNil() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.IsNull(s.C(FieldProvisionSteps)))
	})
}

// ProvisionStepsNotNil applies the NotNil predicate on the "provision_steps" field.
func ProvisionStepsNotNil() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s.Where(sql.NotNull(s.C(FieldProvisionSteps)))
	})
}

// HasHostToDisk applies the HasEdge predicate on the "HostToDisk" edge.
func HasHostToDisk() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToDiskTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, HostToDiskTable, HostToDiskColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHostToDiskWith applies the HasEdge predicate on the "HostToDisk" edge with a given conditions (other predicates).
func HasHostToDiskWith(preds ...predicate.Disk) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToDiskInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2O, false, HostToDiskTable, HostToDiskColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasHostToUser applies the HasEdge predicate on the "HostToUser" edge.
func HasHostToUser() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToUserTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, HostToUserTable, HostToUserColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHostToUserWith applies the HasEdge predicate on the "HostToUser" edge with a given conditions (other predicates).
func HasHostToUserWith(preds ...predicate.User) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToUserInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, HostToUserTable, HostToUserColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasHostToEnvironment applies the HasEdge predicate on the "HostToEnvironment" edge.
func HasHostToEnvironment() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToEnvironmentTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, HostToEnvironmentTable, HostToEnvironmentColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHostToEnvironmentWith applies the HasEdge predicate on the "HostToEnvironment" edge with a given conditions (other predicates).
func HasHostToEnvironmentWith(preds ...predicate.Environment) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToEnvironmentInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, HostToEnvironmentTable, HostToEnvironmentColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasHostToIncludedNetwork applies the HasEdge predicate on the "HostToIncludedNetwork" edge.
func HasHostToIncludedNetwork() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToIncludedNetworkTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, HostToIncludedNetworkTable, HostToIncludedNetworkPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasHostToIncludedNetworkWith applies the HasEdge predicate on the "HostToIncludedNetwork" edge with a given conditions (other predicates).
func HasHostToIncludedNetworkWith(preds ...predicate.IncludedNetwork) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(HostToIncludedNetworkInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, HostToIncludedNetworkTable, HostToIncludedNetworkPrimaryKey...),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasDependOnHostToHostDependency applies the HasEdge predicate on the "DependOnHostToHostDependency" edge.
func HasDependOnHostToHostDependency() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(DependOnHostToHostDependencyTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, DependOnHostToHostDependencyTable, DependOnHostToHostDependencyColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasDependOnHostToHostDependencyWith applies the HasEdge predicate on the "DependOnHostToHostDependency" edge with a given conditions (other predicates).
func HasDependOnHostToHostDependencyWith(preds ...predicate.HostDependency) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(DependOnHostToHostDependencyInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, DependOnHostToHostDependencyTable, DependOnHostToHostDependencyColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasDependByHostToHostDependency applies the HasEdge predicate on the "DependByHostToHostDependency" edge.
func HasDependByHostToHostDependency() predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(DependByHostToHostDependencyTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, DependByHostToHostDependencyTable, DependByHostToHostDependencyColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasDependByHostToHostDependencyWith applies the HasEdge predicate on the "DependByHostToHostDependency" edge with a given conditions (other predicates).
func HasDependByHostToHostDependencyWith(preds ...predicate.HostDependency) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(DependByHostToHostDependencyInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, true, DependByHostToHostDependencyTable, DependByHostToHostDependencyColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Host) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Host) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
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
func Not(p predicate.Host) predicate.Host {
	return predicate.Host(func(s *sql.Selector) {
		p(s.Not())
	})
}
