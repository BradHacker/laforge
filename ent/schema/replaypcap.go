package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// ReplayPcap holds the schema definition for the ReplayPcap entity.
type ReplayPcap struct {
	ent.Schema
}

// Fields of the ReplayPcap.
func (ReplayPcap) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("hcl_id").
			StructTag(`hcl:"id,label"`),
		field.String("source_type").
			StructTag(`hcl:"source_type,attr"`),
		field.String("source").
			StructTag(`hcl:"source,attr"`),
		field.Bool("template").
			StructTag(`hcl:"template,optional"`),
		field.Bool("disabled").
			StructTag(`hcl:"disabled,optional"`),
		field.String("abs_path").
			StructTag(`hcl:"abs_path,optional"`),
		field.JSON("tags", map[string]string{}).
			StructTag(`hcl:"tags,optional"`),
	}
}

// Edges of the ReplayPcap.
func (ReplayPcap) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("Environment", Environment.Type).
			Ref("ReplayPcaps").
			Unique(),
	}
}
