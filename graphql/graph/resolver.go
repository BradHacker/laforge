package graph

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/gen0cide/laforge/ent"
	"github.com/gen0cide/laforge/graphql/auth"
	"github.com/gen0cide/laforge/graphql/graph/generated"
	"github.com/gen0cide/laforge/graphql/graph/model"
	"github.com/gen0cide/laforge/server/utils"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

//go:generate go run github.com/99designs/gqlgen generate

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

// Resolver Specify all the options that are able to be resolved here
// Resolver is the resolver root.
type Resolver struct {
	client        *ent.Client
	rdb           *redis.Client
	laforgeConfig *utils.ServerConfig
}

// NewSchema creates a graphql executable schema.
func NewSchema(client *ent.Client, rdb *redis.Client) graphql.ExecutableSchema {
	laforgeConfig, err := utils.LoadServerConfig()
	if err != nil {
		logrus.Errorf("failed to load LaForge config: %v", err)
		return nil
	}

	GQLConfig := generated.Config{
		Resolvers: &Resolver{
			client:        client,
			rdb:           rdb,
			laforgeConfig: laforgeConfig,
		},
	}
	GQLConfig.Directives.HasRole = func(ctx context.Context, obj interface{}, next graphql.Resolver, roles []model.RoleLevel) (res interface{}, err error) {
		currentUser, err := auth.ForContext(ctx)

		if err != nil {
			return nil, err
		}

		for _, role := range roles {
			if role.String() == string(currentUser.Role) {
				return next(ctx)
			}
		}
		return nil, &gqlerror.Error{
			Message: "not authorized",
			Extensions: map[string]interface{}{
				"code": "401",
			},
		}

	}
	return generated.NewExecutableSchema(GQLConfig)
}
