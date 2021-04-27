// Code generated by entc, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/gen0cide/laforge/ent/ginfilemiddleware"
	"github.com/gen0cide/laforge/ent/provisionedhost"
	"github.com/gen0cide/laforge/ent/provisioningstep"
)

// GinFileMiddleware is the model entity for the GinFileMiddleware schema.
type GinFileMiddleware struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// URLID holds the value of the "url_id" field.
	URLID string `json:"url_id,omitempty"`
	// FilePath holds the value of the "file_path" field.
	FilePath string `json:"file_path,omitempty"`
	// Accessed holds the value of the "accessed" field.
	Accessed bool `json:"accessed,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the GinFileMiddlewareQuery when eager-loading is set.
	Edges GinFileMiddlewareEdges `json:"edges"`

	// Edges put into the main struct to be loaded via hcl
	// GinFileMiddlewareToProvisionedHost holds the value of the GinFileMiddlewareToProvisionedHost edge.
	HCLGinFileMiddlewareToProvisionedHost *ProvisionedHost `json:"GinFileMiddlewareToProvisionedHost,omitempty"`
	// GinFileMiddlewareToProvisioningStep holds the value of the GinFileMiddlewareToProvisioningStep edge.
	HCLGinFileMiddlewareToProvisioningStep *ProvisioningStep `json:"GinFileMiddlewareToProvisioningStep,omitempty"`
	//

}

// GinFileMiddlewareEdges holds the relations/edges for other nodes in the graph.
type GinFileMiddlewareEdges struct {
	// GinFileMiddlewareToProvisionedHost holds the value of the GinFileMiddlewareToProvisionedHost edge.
	GinFileMiddlewareToProvisionedHost *ProvisionedHost `json:"GinFileMiddlewareToProvisionedHost,omitempty"`
	// GinFileMiddlewareToProvisioningStep holds the value of the GinFileMiddlewareToProvisioningStep edge.
	GinFileMiddlewareToProvisioningStep *ProvisioningStep `json:"GinFileMiddlewareToProvisioningStep,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [2]bool
}

// GinFileMiddlewareToProvisionedHostOrErr returns the GinFileMiddlewareToProvisionedHost value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e GinFileMiddlewareEdges) GinFileMiddlewareToProvisionedHostOrErr() (*ProvisionedHost, error) {
	if e.loadedTypes[0] {
		if e.GinFileMiddlewareToProvisionedHost == nil {
			// The edge GinFileMiddlewareToProvisionedHost was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: provisionedhost.Label}
		}
		return e.GinFileMiddlewareToProvisionedHost, nil
	}
	return nil, &NotLoadedError{edge: "GinFileMiddlewareToProvisionedHost"}
}

// GinFileMiddlewareToProvisioningStepOrErr returns the GinFileMiddlewareToProvisioningStep value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e GinFileMiddlewareEdges) GinFileMiddlewareToProvisioningStepOrErr() (*ProvisioningStep, error) {
	if e.loadedTypes[1] {
		if e.GinFileMiddlewareToProvisioningStep == nil {
			// The edge GinFileMiddlewareToProvisioningStep was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: provisioningstep.Label}
		}
		return e.GinFileMiddlewareToProvisioningStep, nil
	}
	return nil, &NotLoadedError{edge: "GinFileMiddlewareToProvisioningStep"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*GinFileMiddleware) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case ginfilemiddleware.FieldAccessed:
			values[i] = new(sql.NullBool)
		case ginfilemiddleware.FieldID:
			values[i] = new(sql.NullInt64)
		case ginfilemiddleware.FieldURLID, ginfilemiddleware.FieldFilePath:
			values[i] = new(sql.NullString)
		default:
			return nil, fmt.Errorf("unexpected column %q for type GinFileMiddleware", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the GinFileMiddleware fields.
func (gfm *GinFileMiddleware) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case ginfilemiddleware.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			gfm.ID = int(value.Int64)
		case ginfilemiddleware.FieldURLID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field url_id", values[i])
			} else if value.Valid {
				gfm.URLID = value.String
			}
		case ginfilemiddleware.FieldFilePath:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field file_path", values[i])
			} else if value.Valid {
				gfm.FilePath = value.String
			}
		case ginfilemiddleware.FieldAccessed:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field accessed", values[i])
			} else if value.Valid {
				gfm.Accessed = value.Bool
			}
		}
	}
	return nil
}

// QueryGinFileMiddlewareToProvisionedHost queries the "GinFileMiddlewareToProvisionedHost" edge of the GinFileMiddleware entity.
func (gfm *GinFileMiddleware) QueryGinFileMiddlewareToProvisionedHost() *ProvisionedHostQuery {
	return (&GinFileMiddlewareClient{config: gfm.config}).QueryGinFileMiddlewareToProvisionedHost(gfm)
}

// QueryGinFileMiddlewareToProvisioningStep queries the "GinFileMiddlewareToProvisioningStep" edge of the GinFileMiddleware entity.
func (gfm *GinFileMiddleware) QueryGinFileMiddlewareToProvisioningStep() *ProvisioningStepQuery {
	return (&GinFileMiddlewareClient{config: gfm.config}).QueryGinFileMiddlewareToProvisioningStep(gfm)
}

// Update returns a builder for updating this GinFileMiddleware.
// Note that you need to call GinFileMiddleware.Unwrap() before calling this method if this GinFileMiddleware
// was returned from a transaction, and the transaction was committed or rolled back.
func (gfm *GinFileMiddleware) Update() *GinFileMiddlewareUpdateOne {
	return (&GinFileMiddlewareClient{config: gfm.config}).UpdateOne(gfm)
}

// Unwrap unwraps the GinFileMiddleware entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (gfm *GinFileMiddleware) Unwrap() *GinFileMiddleware {
	tx, ok := gfm.config.driver.(*txDriver)
	if !ok {
		panic("ent: GinFileMiddleware is not a transactional entity")
	}
	gfm.config.driver = tx.drv
	return gfm
}

// String implements the fmt.Stringer.
func (gfm *GinFileMiddleware) String() string {
	var builder strings.Builder
	builder.WriteString("GinFileMiddleware(")
	builder.WriteString(fmt.Sprintf("id=%v", gfm.ID))
	builder.WriteString(", url_id=")
	builder.WriteString(gfm.URLID)
	builder.WriteString(", file_path=")
	builder.WriteString(gfm.FilePath)
	builder.WriteString(", accessed=")
	builder.WriteString(fmt.Sprintf("%v", gfm.Accessed))
	builder.WriteByte(')')
	return builder.String()
}

// GinFileMiddlewares is a parsable slice of GinFileMiddleware.
type GinFileMiddlewares []*GinFileMiddleware

func (gfm GinFileMiddlewares) config(cfg config) {
	for _i := range gfm {
		gfm[_i].config = cfg
	}
}
