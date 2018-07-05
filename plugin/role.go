package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
)

type Role struct {
	Name        string        `json:"name" structs:"name" mapstructure:"name"`
	Policies    []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	TTL         time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	MaxTTL      time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	Period      time.Duration `json:"period" structs:"period" mapstructure:"period"`
	MetadataKey string        `json:"metadata_key" structs:"metadata_key" mapstructure:"metadata_key"`
	AuthPeriod  time.Duration `json:"auth_period" structs:"auth_period" mapstructure:"auth_period"`
	AuthLimit   int           `json:"auth_limit" structs:"auth_limit" mapstructure:"auth_limit"`
}

func (r *Role) Validate(sys logical.SystemView) (warnings []string, err error) {
	warnings = []string{}

	if r.MetadataKey == "" {
		return warnings, errors.New("metadata_key cannot be empty")
	}

	if r.AuthPeriod < time.Duration(0) {
		return warnings, errors.New("auth_period cannot be negative")
	}

	if r.AuthLimit < 0 {
		return warnings, errors.New("auth_limit cannot be negative")
	}

	defaultLeaseTTL := sys.DefaultLeaseTTL()
	if r.TTL > defaultLeaseTTL {
		warnings = append(warnings, fmt.Sprintf(
			"Given ttl of %d seconds greater than current mount/system default of %d seconds; ttl will be capped at login time",
			r.TTL/time.Second, defaultLeaseTTL/time.Second))
	}

	defaultMaxTTL := sys.MaxLeaseTTL()
	if r.MaxTTL > defaultMaxTTL {
		warnings = append(warnings, fmt.Sprintf(
			"Given max_ttl of %d seconds greater than current mount/system default of %d seconds; max_ttl will be capped at login time",
			r.MaxTTL/time.Second, defaultMaxTTL/time.Second))
	}

	if r.MaxTTL < time.Duration(0) {
		return warnings, errors.New("max_ttl cannot be negative")
	}

	if r.MaxTTL != 0 && r.MaxTTL < r.TTL {
		return warnings, errors.New("ttl should be shorter than max_ttl")
	}

	if r.Period > sys.MaxLeaseTTL() {
		return warnings, fmt.Errorf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", r.Period, sys.MaxLeaseTTL())
	}

	return warnings, nil
}

func readRole(ctx context.Context, s logical.Storage, name string) (*Role, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("role/%s", name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	role := &Role{}
	err = entry.DecodeJSON(role)
	if err != nil {
		return nil, err
	}

	return role, nil
}
