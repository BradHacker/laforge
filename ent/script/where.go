// Code generated by entc, DO NOT EDIT.

package script

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/gen0cide/laforge/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
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
func IDNotIn(ids ...int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
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
func IDGT(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// HclID applies equality check predicate on the "hcl_id" field. It's identical to HclIDEQ.
func HclID(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldName), v))
	})
}

// Language applies equality check predicate on the "language" field. It's identical to LanguageEQ.
func Language(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldLanguage), v))
	})
}

// Description applies equality check predicate on the "description" field. It's identical to DescriptionEQ.
func Description(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDescription), v))
	})
}

// Source applies equality check predicate on the "source" field. It's identical to SourceEQ.
func Source(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSource), v))
	})
}

// SourceType applies equality check predicate on the "source_type" field. It's identical to SourceTypeEQ.
func SourceType(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSourceType), v))
	})
}

// Cooldown applies equality check predicate on the "cooldown" field. It's identical to CooldownEQ.
func Cooldown(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCooldown), v))
	})
}

// Timeout applies equality check predicate on the "timeout" field. It's identical to TimeoutEQ.
func Timeout(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldTimeout), v))
	})
}

// IgnoreErrors applies equality check predicate on the "ignore_errors" field. It's identical to IgnoreErrorsEQ.
func IgnoreErrors(v bool) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIgnoreErrors), v))
	})
}

// Disabled applies equality check predicate on the "disabled" field. It's identical to DisabledEQ.
func Disabled(v bool) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDisabled), v))
	})
}

// AbsPath applies equality check predicate on the "abs_path" field. It's identical to AbsPathEQ.
func AbsPath(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldAbsPath), v))
	})
}

// HclIDEQ applies the EQ predicate on the "hcl_id" field.
func HclIDEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldHclID), v))
	})
}

// HclIDNEQ applies the NEQ predicate on the "hcl_id" field.
func HclIDNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldHclID), v))
	})
}

// HclIDIn applies the In predicate on the "hcl_id" field.
func HclIDIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
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
func HclIDNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
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
func HclIDGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldHclID), v))
	})
}

// HclIDGTE applies the GTE predicate on the "hcl_id" field.
func HclIDGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldHclID), v))
	})
}

// HclIDLT applies the LT predicate on the "hcl_id" field.
func HclIDLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldHclID), v))
	})
}

// HclIDLTE applies the LTE predicate on the "hcl_id" field.
func HclIDLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldHclID), v))
	})
}

// HclIDContains applies the Contains predicate on the "hcl_id" field.
func HclIDContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldHclID), v))
	})
}

// HclIDHasPrefix applies the HasPrefix predicate on the "hcl_id" field.
func HclIDHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldHclID), v))
	})
}

// HclIDHasSuffix applies the HasSuffix predicate on the "hcl_id" field.
func HclIDHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldHclID), v))
	})
}

// HclIDEqualFold applies the EqualFold predicate on the "hcl_id" field.
func HclIDEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldHclID), v))
	})
}

// HclIDContainsFold applies the ContainsFold predicate on the "hcl_id" field.
func HclIDContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldHclID), v))
	})
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldName), v))
	})
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldName), v))
	})
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
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
func NameNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
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
func NameGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldName), v))
	})
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldName), v))
	})
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldName), v))
	})
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldName), v))
	})
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldName), v))
	})
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldName), v))
	})
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldName), v))
	})
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldName), v))
	})
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldName), v))
	})
}

// LanguageEQ applies the EQ predicate on the "language" field.
func LanguageEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldLanguage), v))
	})
}

// LanguageNEQ applies the NEQ predicate on the "language" field.
func LanguageNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldLanguage), v))
	})
}

// LanguageIn applies the In predicate on the "language" field.
func LanguageIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldLanguage), v...))
	})
}

// LanguageNotIn applies the NotIn predicate on the "language" field.
func LanguageNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldLanguage), v...))
	})
}

// LanguageGT applies the GT predicate on the "language" field.
func LanguageGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldLanguage), v))
	})
}

// LanguageGTE applies the GTE predicate on the "language" field.
func LanguageGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldLanguage), v))
	})
}

// LanguageLT applies the LT predicate on the "language" field.
func LanguageLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldLanguage), v))
	})
}

// LanguageLTE applies the LTE predicate on the "language" field.
func LanguageLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldLanguage), v))
	})
}

// LanguageContains applies the Contains predicate on the "language" field.
func LanguageContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldLanguage), v))
	})
}

// LanguageHasPrefix applies the HasPrefix predicate on the "language" field.
func LanguageHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldLanguage), v))
	})
}

// LanguageHasSuffix applies the HasSuffix predicate on the "language" field.
func LanguageHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldLanguage), v))
	})
}

// LanguageEqualFold applies the EqualFold predicate on the "language" field.
func LanguageEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldLanguage), v))
	})
}

// LanguageContainsFold applies the ContainsFold predicate on the "language" field.
func LanguageContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldLanguage), v))
	})
}

// DescriptionEQ applies the EQ predicate on the "description" field.
func DescriptionEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDescription), v))
	})
}

// DescriptionNEQ applies the NEQ predicate on the "description" field.
func DescriptionNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDescription), v))
	})
}

// DescriptionIn applies the In predicate on the "description" field.
func DescriptionIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
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
func DescriptionNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
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
func DescriptionGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldDescription), v))
	})
}

// DescriptionGTE applies the GTE predicate on the "description" field.
func DescriptionGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldDescription), v))
	})
}

// DescriptionLT applies the LT predicate on the "description" field.
func DescriptionLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldDescription), v))
	})
}

// DescriptionLTE applies the LTE predicate on the "description" field.
func DescriptionLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldDescription), v))
	})
}

// DescriptionContains applies the Contains predicate on the "description" field.
func DescriptionContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldDescription), v))
	})
}

// DescriptionHasPrefix applies the HasPrefix predicate on the "description" field.
func DescriptionHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldDescription), v))
	})
}

// DescriptionHasSuffix applies the HasSuffix predicate on the "description" field.
func DescriptionHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldDescription), v))
	})
}

// DescriptionEqualFold applies the EqualFold predicate on the "description" field.
func DescriptionEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldDescription), v))
	})
}

// DescriptionContainsFold applies the ContainsFold predicate on the "description" field.
func DescriptionContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldDescription), v))
	})
}

// SourceEQ applies the EQ predicate on the "source" field.
func SourceEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSource), v))
	})
}

// SourceNEQ applies the NEQ predicate on the "source" field.
func SourceNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldSource), v))
	})
}

// SourceIn applies the In predicate on the "source" field.
func SourceIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldSource), v...))
	})
}

// SourceNotIn applies the NotIn predicate on the "source" field.
func SourceNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldSource), v...))
	})
}

// SourceGT applies the GT predicate on the "source" field.
func SourceGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldSource), v))
	})
}

// SourceGTE applies the GTE predicate on the "source" field.
func SourceGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldSource), v))
	})
}

// SourceLT applies the LT predicate on the "source" field.
func SourceLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldSource), v))
	})
}

// SourceLTE applies the LTE predicate on the "source" field.
func SourceLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldSource), v))
	})
}

// SourceContains applies the Contains predicate on the "source" field.
func SourceContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldSource), v))
	})
}

// SourceHasPrefix applies the HasPrefix predicate on the "source" field.
func SourceHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldSource), v))
	})
}

// SourceHasSuffix applies the HasSuffix predicate on the "source" field.
func SourceHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldSource), v))
	})
}

// SourceEqualFold applies the EqualFold predicate on the "source" field.
func SourceEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldSource), v))
	})
}

// SourceContainsFold applies the ContainsFold predicate on the "source" field.
func SourceContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldSource), v))
	})
}

// SourceTypeEQ applies the EQ predicate on the "source_type" field.
func SourceTypeEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSourceType), v))
	})
}

// SourceTypeNEQ applies the NEQ predicate on the "source_type" field.
func SourceTypeNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldSourceType), v))
	})
}

// SourceTypeIn applies the In predicate on the "source_type" field.
func SourceTypeIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldSourceType), v...))
	})
}

// SourceTypeNotIn applies the NotIn predicate on the "source_type" field.
func SourceTypeNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldSourceType), v...))
	})
}

// SourceTypeGT applies the GT predicate on the "source_type" field.
func SourceTypeGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldSourceType), v))
	})
}

// SourceTypeGTE applies the GTE predicate on the "source_type" field.
func SourceTypeGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldSourceType), v))
	})
}

// SourceTypeLT applies the LT predicate on the "source_type" field.
func SourceTypeLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldSourceType), v))
	})
}

// SourceTypeLTE applies the LTE predicate on the "source_type" field.
func SourceTypeLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldSourceType), v))
	})
}

// SourceTypeContains applies the Contains predicate on the "source_type" field.
func SourceTypeContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldSourceType), v))
	})
}

// SourceTypeHasPrefix applies the HasPrefix predicate on the "source_type" field.
func SourceTypeHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldSourceType), v))
	})
}

// SourceTypeHasSuffix applies the HasSuffix predicate on the "source_type" field.
func SourceTypeHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldSourceType), v))
	})
}

// SourceTypeEqualFold applies the EqualFold predicate on the "source_type" field.
func SourceTypeEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldSourceType), v))
	})
}

// SourceTypeContainsFold applies the ContainsFold predicate on the "source_type" field.
func SourceTypeContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldSourceType), v))
	})
}

// CooldownEQ applies the EQ predicate on the "cooldown" field.
func CooldownEQ(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCooldown), v))
	})
}

// CooldownNEQ applies the NEQ predicate on the "cooldown" field.
func CooldownNEQ(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldCooldown), v))
	})
}

// CooldownIn applies the In predicate on the "cooldown" field.
func CooldownIn(vs ...int) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldCooldown), v...))
	})
}

// CooldownNotIn applies the NotIn predicate on the "cooldown" field.
func CooldownNotIn(vs ...int) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldCooldown), v...))
	})
}

// CooldownGT applies the GT predicate on the "cooldown" field.
func CooldownGT(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldCooldown), v))
	})
}

// CooldownGTE applies the GTE predicate on the "cooldown" field.
func CooldownGTE(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldCooldown), v))
	})
}

// CooldownLT applies the LT predicate on the "cooldown" field.
func CooldownLT(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldCooldown), v))
	})
}

// CooldownLTE applies the LTE predicate on the "cooldown" field.
func CooldownLTE(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldCooldown), v))
	})
}

// TimeoutEQ applies the EQ predicate on the "timeout" field.
func TimeoutEQ(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldTimeout), v))
	})
}

// TimeoutNEQ applies the NEQ predicate on the "timeout" field.
func TimeoutNEQ(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldTimeout), v))
	})
}

// TimeoutIn applies the In predicate on the "timeout" field.
func TimeoutIn(vs ...int) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldTimeout), v...))
	})
}

// TimeoutNotIn applies the NotIn predicate on the "timeout" field.
func TimeoutNotIn(vs ...int) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldTimeout), v...))
	})
}

// TimeoutGT applies the GT predicate on the "timeout" field.
func TimeoutGT(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldTimeout), v))
	})
}

// TimeoutGTE applies the GTE predicate on the "timeout" field.
func TimeoutGTE(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldTimeout), v))
	})
}

// TimeoutLT applies the LT predicate on the "timeout" field.
func TimeoutLT(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldTimeout), v))
	})
}

// TimeoutLTE applies the LTE predicate on the "timeout" field.
func TimeoutLTE(v int) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldTimeout), v))
	})
}

// IgnoreErrorsEQ applies the EQ predicate on the "ignore_errors" field.
func IgnoreErrorsEQ(v bool) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIgnoreErrors), v))
	})
}

// IgnoreErrorsNEQ applies the NEQ predicate on the "ignore_errors" field.
func IgnoreErrorsNEQ(v bool) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldIgnoreErrors), v))
	})
}

// DisabledEQ applies the EQ predicate on the "disabled" field.
func DisabledEQ(v bool) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDisabled), v))
	})
}

// DisabledNEQ applies the NEQ predicate on the "disabled" field.
func DisabledNEQ(v bool) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDisabled), v))
	})
}

// AbsPathEQ applies the EQ predicate on the "abs_path" field.
func AbsPathEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldAbsPath), v))
	})
}

// AbsPathNEQ applies the NEQ predicate on the "abs_path" field.
func AbsPathNEQ(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldAbsPath), v))
	})
}

// AbsPathIn applies the In predicate on the "abs_path" field.
func AbsPathIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.In(s.C(FieldAbsPath), v...))
	})
}

// AbsPathNotIn applies the NotIn predicate on the "abs_path" field.
func AbsPathNotIn(vs ...string) predicate.Script {
	v := make([]interface{}, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.Script(func(s *sql.Selector) {
		// if not arguments were provided, append the FALSE constants,
		// since we can't apply "IN ()". This will make this predicate falsy.
		if len(v) == 0 {
			s.Where(sql.False())
			return
		}
		s.Where(sql.NotIn(s.C(FieldAbsPath), v...))
	})
}

// AbsPathGT applies the GT predicate on the "abs_path" field.
func AbsPathGT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldAbsPath), v))
	})
}

// AbsPathGTE applies the GTE predicate on the "abs_path" field.
func AbsPathGTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldAbsPath), v))
	})
}

// AbsPathLT applies the LT predicate on the "abs_path" field.
func AbsPathLT(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldAbsPath), v))
	})
}

// AbsPathLTE applies the LTE predicate on the "abs_path" field.
func AbsPathLTE(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldAbsPath), v))
	})
}

// AbsPathContains applies the Contains predicate on the "abs_path" field.
func AbsPathContains(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldAbsPath), v))
	})
}

// AbsPathHasPrefix applies the HasPrefix predicate on the "abs_path" field.
func AbsPathHasPrefix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldAbsPath), v))
	})
}

// AbsPathHasSuffix applies the HasSuffix predicate on the "abs_path" field.
func AbsPathHasSuffix(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldAbsPath), v))
	})
}

// AbsPathEqualFold applies the EqualFold predicate on the "abs_path" field.
func AbsPathEqualFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldAbsPath), v))
	})
}

// AbsPathContainsFold applies the ContainsFold predicate on the "abs_path" field.
func AbsPathContainsFold(v string) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldAbsPath), v))
	})
}

// HasScriptToUser applies the HasEdge predicate on the "ScriptToUser" edge.
func HasScriptToUser() predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptToUserTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ScriptToUserTable, ScriptToUserColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasScriptToUserWith applies the HasEdge predicate on the "ScriptToUser" edge with a given conditions (other predicates).
func HasScriptToUserWith(preds ...predicate.User) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptToUserInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ScriptToUserTable, ScriptToUserColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasScriptToFinding applies the HasEdge predicate on the "ScriptToFinding" edge.
func HasScriptToFinding() predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptToFindingTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ScriptToFindingTable, ScriptToFindingColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasScriptToFindingWith applies the HasEdge predicate on the "ScriptToFinding" edge with a given conditions (other predicates).
func HasScriptToFindingWith(preds ...predicate.Finding) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptToFindingInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, ScriptToFindingTable, ScriptToFindingColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasScriptToEnvironment applies the HasEdge predicate on the "ScriptToEnvironment" edge.
func HasScriptToEnvironment() predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptToEnvironmentTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, ScriptToEnvironmentTable, ScriptToEnvironmentColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasScriptToEnvironmentWith applies the HasEdge predicate on the "ScriptToEnvironment" edge with a given conditions (other predicates).
func HasScriptToEnvironmentWith(preds ...predicate.Environment) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.To(ScriptToEnvironmentInverseTable, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, ScriptToEnvironmentTable, ScriptToEnvironmentColumn),
		)
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Script) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Script) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
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
func Not(p predicate.Script) predicate.Script {
	return predicate.Script(func(s *sql.Selector) {
		p(s.Not())
	})
}
