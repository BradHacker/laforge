package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Team holds the schema definition for the Team entity.
type Team struct {
	ent.Schema
}

// Fields of the Team.
func (Team) Fields() []ent.Field {
	return []ent.Field{
		field.Int("team_number"),
	}
}

// Edges of the Team.
func (Team) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("TeamToBuild", Build.Type).Unique().Required(),
		edge.To("TeamToStatus", Status.Type).Unique(),
		edge.From("TeamToProvisionedNetwork", ProvisionedNetwork.Type).
			Ref("ProvisionedNetworkToTeam").
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
		edge.From("TeamToPlan", Plan.Type).
			Ref("PlanToTeam").
			Unique().
			Annotations(entsql.Annotation{
				OnDelete: entsql.Cascade,
			}),
	}
}
