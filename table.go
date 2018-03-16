package snmpquery

import (
	"strings"

	"github.com/pkg/errors"

	"github.com/sleepinggenius2/gosmi/models"
	"github.com/sleepinggenius2/gosmi/types"
	"github.com/sleepinggenius2/gosnmp"
)

// Column represents a table column
type Column struct {
	Name   string
	Node   models.ColumnNode
	Format models.Format
}

// Row represents a table row
type Row struct {
	Index  []models.Value
	Values map[string]models.Value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Table struct {
	Node    models.TableNode
	columns []Column
}

func (t *Table) Column(node models.ColumnNode, format ...models.Format) {
	t.NamedColumn(node.Name, node, format...)
}

func (t *Table) NamedColumn(name string, node models.ColumnNode, format ...models.Format) {
	column := Column{Name: name, Node: node, Format: models.ResolveFormat(format)}
	t.columns = append(t.columns, column)
}

func (t *Table) Columns() []Column {
	if len(t.columns) > 0 {
		return t.columns
	}
	columnList := t.Node.Columns()
	columns := make([]Column, len(columnList))
	for i, column := range columnList {
		columns[i] = Column{Name: column.Name, Node: column}
	}
	return columns
}

func NewTable(node models.TableNode) Table {
	return Table{Node: node}
}

// Table queries the client for the given table at the given index
func (c Client) Table(table Table, index ...string) (results map[string]Row, err error) {
	columns := table.Columns()
	numColumns := len(columns)
	if numColumns == 0 {
		return nil, errors.New("No columns given")
	}

	tableIndex := table.Node.Index()

	indexLen := len(index)
	if indexLen == len(tableIndex) {
		return c.singleRow(table.Node, columns, index)
	}

	results = make(map[string]Row)

	numIndices := len(tableIndex) - indexLen

	indexValueFormatters := make(map[string]models.ValueFormatter, numIndices)
	indices := make([]string, numIndices)
	for i, indexNode := range tableIndex {
		if i < indexLen {
			continue
		}
		indexValueFormatters[indexNode.Name] = indexNode.Type.GetValueFormatter(models.FormatAll)
		indices[i-indexLen] = indexNode.Name
	}

	for _, column := range columns {
		//TODO: Check if column is part of the table

		rootOid := column.Node.OidFormatted
		if len(index) > 0 {
			rootOid += "." + strings.Join(index, ".")
		}

		fn := walkFunc(table.Node, column, index, rootOid, indexValueFormatters, numColumns, &results)
		err = c.snmp.BulkWalk(rootOid, fn)
		if err != nil {
			return
		}
	}

	return
}

func (c Client) singleRow(table models.TableNode, columns []Column, index []string) (results map[string]Row, err error) {
	columnIndex := strings.Join(index, ".")

	q := Query{}
	for _, column := range columns {
		q.NamedColumn(column.Name, column.Node, columnIndex, column.Format)
	}

	result, err := c.GetAll(q)
	if err != nil {
		return
	}

	row := Row{
		Index:  make([]models.Value, len(index)),
		Values: result,
	}

	for i, indexValue := range index {
		row.Index[i] = models.Value{Formatted: indexValue, Raw: indexValue}
	}

	return map[string]Row{columnIndex: row}, nil
}

func walkFunc(table models.TableNode, column Column, index []string, rootOid string, valueFormatters map[string]models.ValueFormatter, numColumns int, results *map[string]Row) func(gosnmp.SnmpPDU) error {
	indexLen := len(index)
	numIndices := len(table.Row.Index) - indexLen
	valueFormatter := column.Node.Type.GetValueFormatter(column.Format)
	return func(pdu gosnmp.SnmpPDU) error {
		switch pdu.Type {
		case gosnmp.NoSuchObject:
			return errors.New("No such object for " + column.Node.Name)
		case gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
			return nil
		}

		index := pdu.Name[len(rootOid)+2:]
		if _, ok := (*results)[index]; !ok {
			indexParts := pdu.Oid[column.Node.OidLen+uint(indexLen):]
			rowIndex := getIndex(table, indexLen, numIndices, indexParts, valueFormatters)
			(*results)[index] = Row{
				Index:  rowIndex,
				Values: make(map[string]models.Value, numColumns),
			}
		}
		var val interface{}
		switch column.Node.Type.BaseType {
		case types.BaseTypeOctetString, types.BaseTypeBits:
			val = pdu.Value
		default:
			val = gosnmp.ToBigInt(pdu.Value).Int64()
		}
		(*results)[index].Values[column.Name] = valueFormatter(val)
		return nil
	}
}

func getIndex(table models.TableNode, indexLen int, numIndices int, indexParts []int, valueFormatters map[string]models.ValueFormatter) (index []models.Value) {
	index = make([]models.Value, numIndices)
	for j, indexNode := range table.Row.Index {
		if j < indexLen {
			continue
		}
		var val interface{}
		if indexNode.Type.BaseType == types.BaseTypeOctetString {
			maxLen := len(indexParts) - numIndices + j - indexLen + 1
			if len(indexNode.Type.Ranges) == 1 {
				r := indexNode.Type.Ranges[0]
				maxValue := int(r.MaxValue)
				l := min(maxValue, maxLen)
				val = indexParts[:l]
				indexParts = indexParts[l:]
			} else {
				val = indexParts[:maxLen]
				indexParts = indexParts[maxLen:]
			}
		} else {
			val = int64(indexParts[0])
			indexParts = indexParts[1:]
		}
		index[j-indexLen] = valueFormatters[indexNode.Name](val)
	}

	return
}
