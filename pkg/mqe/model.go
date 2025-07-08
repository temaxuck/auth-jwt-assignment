// MQE - Micro SQL Query Engine.
//
// It was created on the fly to eliminate repetitive code and is not intended for production use.
//
// Author: Darizhapov Artem

package mqe

import (
	"fmt"
	"reflect"
	"strings"
)

// Returns sql column names (or definitions if the second argument is `true`) in the fields'
// declaration order in the struct
func GetColumns(m interface{}, createTableMode bool) ([]string, error) {
	mV := reflect.ValueOf(m)
	if mV.Kind() == reflect.Ptr {
		mV = mV.Elem()
	}
	mT := mV.Type()
	if mT.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected a struct or pointer to struct")
	}
	var columns []string

	for i := 0; i < mV.NumField(); i++ {
		field := mT.Field(i)
		tagRaw := field.Tag.Get(MQE_GOLANG_TAG)
		if tagRaw == "" {
			continue
		}

		tag, err := ParseModelSQLTag(tagRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tag (%s): %w", tagRaw, err)
		}

		col := tag.SQLName
		if createTableMode {
			col += " " + tag.SQLType
			if len(tag.SQLOpts) > 0 {
				col += " " + strings.Join(tag.SQLOpts, " ")
			}
		}
		columns = append(columns, col)
	}

	if len(columns) == 0 {
		return nil, fmt.Errorf("no sql-convertable columns found")
	}

	return columns, nil
}

func GetFC(m interface{}) (map[string]string, error) {
	mV := reflect.ValueOf(m)
	if mV.Kind() == reflect.Ptr {
		mV = mV.Elem()
	}
	mT := mV.Type()
	if mT.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected a struct or pointer to struct")
	}

	fc := make(map[string]string, mV.NumField())

	for i := 0; i < mV.NumField(); i++ {
		field := mT.Field(i)
		tagRaw := field.Tag.Get(MQE_GOLANG_TAG)
		if tagRaw == "" {
			continue
		}

		tag, err := ParseModelSQLTag(tagRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tag (%s): %w", tagRaw, err)
		}

		fc[field.Name] = tag.SQLName
	}

	if len(fc) == 0 {
		return nil, fmt.Errorf("no sql-convertable columns found")
	}

	return fc, nil
}
