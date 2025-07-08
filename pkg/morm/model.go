package morm

import (
	"fmt"
	"reflect"
	"strings"
)

type ModelSQL interface {
	TableName() string
}

func CreateTable(m ModelSQL) (QuerySQL, error) {
	tableName := m.TableName()
	columns, err := createTableModelColumns(m)
	if err != nil {
		return "", err
	}

	return QuerySQL("CREATE TABLE IF NOT EXISTS " + tableName + " (\n  " + strings.Join(columns, ",\n  ") + "\n);"), nil
}

func createTableModelColumns(m ModelSQL) ([]string, error) {
	mV := reflect.ValueOf(m)
	mT := mV.Type()

	var columns []string

	for i := range mV.NumField() {
		field := mT.Field(i)
		tagRaw := field.Tag.Get("morm")
		if tagRaw != "" {
			tag, err := ParseModelSQLTag(tagRaw)
			if err != nil {
				return nil, fmt.Errorf("tag (%s): %w", err)
			}
			col := tag.SQLName + " " + tag.SQLType
			if len(tag.SQLOpts) > 0 {
				col += " " + strings.Join(tag.SQLOpts, " ")
			}
			columns = append(columns, col)
		}
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("no sql-convertable columns found")
	}

	return columns, nil
}
