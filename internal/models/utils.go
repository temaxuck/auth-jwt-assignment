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
