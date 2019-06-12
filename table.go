package snmpquery

import (
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

func (c Column) FormatValue(value interface{}) models.Value {
	return c.Node.FormatValue(value, c.Format)
}

// Row represents a table row
type Row struct {
	Index  []models.Value
	Values map[string]models.Value
}

type Table struct {
	IndexFormat  models.Format
	ColumnFormat models.Format
	Node         models.TableNode
	columns      []Column
}

func (t *Table) Column(node models.ColumnNode, format ...models.Format) {
	t.NamedColumn(node.Name, node, format...)
}

func (t *Table) NamedColumn(name string, node models.ColumnNode, format ...models.Format) {
	column := Column{Name: name, Node: node, Format: models.ResolveFormat(format, t.ColumnFormat)}
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

func NewTable(node models.TableNode, indexFormat ...models.Format) Table {
	return Table{Node: node, IndexFormat: models.ResolveFormat(indexFormat, models.FormatNone)}
}

// Table queries the client for the given table at the given index
func (c Client) Table(table Table, index ...interface{}) (results map[string]Row, err error) {
	columns := table.Columns()
	numColumns := len(columns)
	if numColumns == 0 {
		return nil, errors.New("No columns given")
	}

	indexLen := len(index)
	if indexLen == len(table.Node.Index()) {
		return c.singleRow(table.Node, columns, index)
	}

	indexSlice, err := table.Node.BuildIndex(index...)
	if err != nil {
		return nil, errors.Wrap(err, "Build index")
	}

	results = make(map[string]Row)
	for _, column := range columns {
		if !table.Node.ParentOf(column.Node.BaseNode) {
			return nil, errors.Errorf("Column %s is not in table %s", column.Node.Name, table.Node.Name)
		}

		rootOid := column.Node.Oid
		if len(indexSlice) != 0 {
			rootOid = append(rootOid, indexSlice...)
		}

		fn := walkFunc(table, column, numColumns, indexLen, rootOid, results)
		err = c.snmp.BulkWalkOID(rootOid, fn)
		if err != nil {
			return
		}
	}

	return
}

func (c Client) singleRow(table models.TableNode, columns []Column, index []interface{}) (results map[string]Row, err error) {
	indexSlice, err := table.BuildIndex(index...)
	if err != nil {
		return nil, errors.Wrap(err, "Build index")
	}

	q := Query{}
	for _, column := range columns {
		q.NamedColumn(column.Name, column.Node, indexSlice, column.Format)
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
		row.Index[i] = models.Value{Raw: indexValue}
	}

	return map[string]Row{GetIndexKey(indexSlice): row}, nil
}

func walkFunc(table Table, column Column, numColumns int, indexLen int, rootOid types.Oid, results map[string]Row) gosnmp.WalkFunc {
	oidLen := len(rootOid)

	return func(pdu gosnmp.SnmpPDU) error {
		switch pdu.Type {
		case gosnmp.NoSuchObject:
			return errors.New("No such object for " + column.Node.Name)
		case gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
			return nil
		}

		indexParts := pdu.Oid[oidLen:]
		index := GetIndexKey(indexParts)
		if _, ok := results[index]; !ok {
			rowIndex := getIndex(table.Node, indexLen, indexParts, table.IndexFormat)
			results[index] = Row{
				Index:  rowIndex,
				Values: make(map[string]models.Value, numColumns),
			}
		}
		var val interface{}
		switch column.Node.Type.BaseType {
		case types.BaseTypeOctetString, types.BaseTypeBits:
			val = pdu.Value
		default:
			val, _ = models.ToInt64(pdu.Value)
		}
		results[index].Values[column.Name] = column.FormatValue(val)
		return nil
	}
}

func GetIndexKey(indexParts types.Oid) string {
	indexBytes := make([]byte, 4*len(indexParts))
	for i, part := range indexParts {
		indexBytes[i<<2] = byte((part >> 24) & 0xff)
		indexBytes[i<<2+1] = byte((part >> 16) & 0xff)
		indexBytes[i<<2+2] = byte((part >> 8) & 0xff)
		indexBytes[i<<2+3] = byte(part & 0xff)
	}
	return string(indexBytes)
}

func getIndex(table models.TableNode, indexLen int, indexParts types.Oid, indexFormat models.Format) (index []models.Value) {
	indices := table.Index()
	numIndices := len(indices)
	index = make([]models.Value, numIndices-indexLen)
	implied := table.Implied()

	for i := 0; i < numIndices-indexLen; i++ {
		indexNode := indices[i+indexLen]
		var val interface{}
		switch indexNode.Type.BaseType {
		case types.BaseTypeObjectIdentifier:
			var oidLen int
			if i < numIndices-indexLen-1 || !implied {
				oidLen = int(indexParts[0])
				indexParts = indexParts[1:]
				if oidLen > len(indexParts) {
					// TODO: This shouldn't happen, what do we do?
					return
				}
			} else {
				oidLen = len(indexParts)
			}
			val = indexParts[:oidLen]
			indexParts = indexParts[oidLen:]
		case types.BaseTypeOctetString, types.BaseTypeBits:
			var strLen int
			if i < numIndices-indexLen-1 || !implied {
				strLen = int(indexParts[0])
				indexParts = indexParts[1:]
				if strLen > len(indexParts) {
					// TODO: This shouldn't happen, what do we do?
					return
				}
			} else {
				strLen = len(indexParts)
			}
			bytes := make([]byte, strLen)
			for j := 0; j < strLen; j++ {
				if indexParts[j] > 0xff {
					// TODO: This shouldn't happen, what do we do?
					return
				}
				bytes[j] = byte(indexParts[j])
			}
			val = bytes
			indexParts = indexParts[strLen:]
		default:
			val = indexParts[0]
			indexParts = indexParts[1:]
		}
		index[i] = indexNode.FormatValue(val, indexFormat)
	}

	return
}
