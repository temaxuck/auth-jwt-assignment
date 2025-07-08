package models

import (
	"fmt"
	"strings"
)

// Returns $1, ... $nArgs
func argsPlaceholderString(nArgs uint) (string, error) {
	if nArgs == 0 {
		return "", fmt.Errorf("Number of arguments must be positive (> 0)")
	}

	var p strings.Builder
	var i uint
	for i = 1; i <= nArgs; i++ {
		if i > 1 {
			p.WriteString(", ")
		}
		fmt.Fprintf(&p, "$%d", i)
	}

	return p.String(), nil
}

func parseClauseExpr(rt *RefreshToken, fv map[string]any, startArgc int) ([]string, []interface{}, int, error) {
	fc, err := GetFC(rt)
	if err != nil {
		return nil, nil, -1, err
	}

	var clauses []string
	var args []interface{}
	var argc int
	if startArgc < 1 {
		argc = 1
	} else {
		argc = startArgc
	}

	for c, v := range fv {
		sqlCol, ok := fc[c]
		if !ok {
			return nil, nil, -1, fmt.Errorf("invalid column %s", c)
		}
		clauses = append(clauses, fmt.Sprintf("%q = $%d", sqlCol, argc))
		args = append(args, v)
		argc++
	}

	return clauses, args, argc, nil
}
