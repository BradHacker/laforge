package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Validation holds the schema definition for the Validation entity.
type Validation struct {
	ent.Schema
}

// Fields of the Validation.
func (Validation) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.String("hcl_id").
			StructTag(`hcl:"id,label"`),
		field.Enum("validation_type").
			Values(
				"linux-apt-installed",
				"net-tcp-open",
				"net-udp-open",
				"net-http-content-regex",
				"file-exists",
				"file-hash",
				"file-content-regex",
				"dir-exists",
				"user-exists",
				"user-group-membership",
				"host-port-open",
				"host-process-running",
				"host-service-state",
				"net-icmp",
				"file-content-string",
				"file-permission",
			).
			StructTag(`hcl:"validation_type"`),
		field.String("hash").StructTag(`hcl:"hash,optional"`).Optional(),
		field.String("regex").StructTag(`hcl:"regex,optional"`).Optional(),
		field.String("ip").StructTag(`hcl:"ip,optional"`).Optional(),
		field.String("url").StructTag(`hcl:"url,optional"`).Optional(),
		field.Int("port").StructTag(`hcl:"port,optional"`).Optional(),
		field.String("hostname").StructTag(`hcl:"hostname,optional"`).Optional(),
		field.JSON("nameservers", []string{}).StructTag(`hcl:"nameservers,optional"`).Optional(),
		field.String("package_name").StructTag(`hcl:"package_name,optional"`).Optional(),
		field.String("username").StructTag(`hcl:"username,optional"`).Optional(),
		field.String("group_name").StructTag(`hcl:"group_name,optional"`).Optional(),
		field.String("file_path").StructTag(`hcl:"file_path,optional"`).Optional(),
		field.String("search_string").StructTag(`hcl:"search_string,optional"`).Optional(),
		field.String("service_name").StructTag(`hcl:"service_name,optional"`).Optional(),
		field.String("file_permission").StructTag(`hcl:"file_permission,optional"`).Optional(),
		field.Enum("service_status").
			Values(
				"active",
				"inactive",
				"enabled",
				"disabled",
				"static",
				"masked",
				"alias",
				"linked",
			).
			StructTag(`hcl:"service_status,optional"`).
			Default("active"),
		field.String("process_name").StructTag(`hcl:"process_name,optional"`).Optional(),
	}
}

// Edges of the Validation.
func (Validation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("Users", User.Type).
			StructTag(`hcl:"maintainer,block"`),
		edge.From("Environment", Environment.Type).
			Ref("Validations").
			Unique(),
	}
}
