package snmpquery

import (
	"github.com/sleepinggenius2/gosmi/models"
)

// QueryItem contains the information for a single query item
type QueryItem struct {
	Format models.ValueFormatter
	Name   string
	Oid    string
}

// Query contains the items to query
type Query struct {
	Items []QueryItem
}

func (q *Query) add(name string, t models.Type, oid string, formats []models.Format) {
	format := models.FormatAll
	if len(formats) > 0 {
		format = models.FormatNone
		for _, f := range formats {
			format |= f
		}
	}

	item := QueryItem{
		Format: t.GetValueFormatter(format),
		Name:   name,
		Oid:    oid,
	}
	q.Items = append(q.Items, item)
}

// Column is a helper method to add an implicitly named column to the query
func (q *Query) Column(node models.ColumnNode, index string, format ...models.Format) {
	oid := node.OidFormatted + "." + index
	q.add(node.Name, node.Type, oid, format)
}

// NamedColumn is a helper method to add an explicitly named column to the query
func (q *Query) NamedColumn(name string, node models.ColumnNode, index string, format ...models.Format) {
	oid := node.OidFormatted + "." + index
	q.add(name, node.Type, oid, format)
}

// NamedScalar is a helper method to add an explicitly named scalar to the query
func (q *Query) NamedScalar(name string, node models.ScalarNode, format ...models.Format) {
	q.add(name, node.Type, node.OidFormatted, format)
}

// Scalar is a helper method to add an implicitly named scalar to the query
func (q *Query) Scalar(node models.ScalarNode, format ...models.Format) {
	q.add(node.Name, node.Type, node.OidFormatted, format)
}
