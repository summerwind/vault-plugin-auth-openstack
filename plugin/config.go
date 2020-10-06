package plugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

type Config struct {
	AuthURL               string   `json:"auth_url" structs:"auth_url" mapstructure:"auth_url"`
	Token                 string   `json:"token" structs:"token" mapstructure:"token"`
	UserID                string   `json:"user_id" structs:"user_id" mapstructure:"user_id"`
	Username              string   `json:"username" structs:"username" mapstructure:"username"`
	Password              string   `json:"password" structs:"password" mapstructure:"password"`
	ProjectID             string   `json:"project_id" structs:"project_id" mapstructure:"project_id"`
	ProjectName           string   `json:"project_name" structs:"project_name" mapstructure:"project_name"`
	TenantID              string   `json:"tenant_id" structs:"tenant_id" mapstructure:"tenant_id"`
	TenantName            string   `json:"tenant_name" structs:"tenant_name" mapstructure:"tenant_name"`
	UserDomainID          string   `json:"user_domain_id" structs:"user_domain_id" mapstructure:"user_domain_id"`
	UserDomainName        string   `json:"user_domain_name" structs:"user_domain_name" mapstructure:"user_domain_name"`
	ProjectDomainID       string   `json:"project_domain_id" structs:"project_domain_id" mapstructure:"project_domain_id"`
	ProjectDomainName     string   `json:"project_domain_name" structs:"project_domain_name" mapstructure:"project_domain_name"`
	DomainID              string   `json:"domain_id" structs:"domain_id" mapstructure:"domain_id"`
	DomainName            string   `json:"domain_name" structs:"domain_name" mapstructure:"domain_name"`
	RequestAddressHeaders []string `json:"request_address_headers" structs:"request_address_headers" mapstructure:"request_address_headers"`
}

func readConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := &Config{}
	err = entry.DecodeJSON(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
