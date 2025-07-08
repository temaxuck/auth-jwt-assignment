package models

import (
	"errors"
	"strings"
)

const MQE_GOLANG_TAG = "mqe"

type ModelSQLTag struct {
	SQLName string
	SQLType string
	SQLOpts []string
}

func ParseModelSQLTag(tag string) (*ModelSQLTag, error) {
	parts := strings.Split(tag, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) < 2 {
		return nil, errors.New("invalid tag structure")
	}
	return &ModelSQLTag{
		SQLName: parts[0],
		SQLType: parts[1],
		SQLOpts: parts[2:],
	}, nil
}
