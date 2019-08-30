package plugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configSynopsis = "Configures the OpenStack API information."
const configDescription = `
The OpenStack Auth backend validates the instance infromation and verifies 
their existence with the OpenStack API. This endpoint configures the 
information to access the OpenStack API.
`

var configFields map[string]*framework.FieldSchema = map[string]*framework.FieldSchema{
	"auth_url": {
		Type:        framework.TypeString,
		Description: "Keystone endpoint URL.",
	},
	"token": {
		Type:        framework.TypeString,
		Description: "Pre-generated authentication token.",
	},
	"user_id": {
		Type:        framework.TypeString,
		Description: "Unique ID of the user.",
	},
	"username": {
		Type:        framework.TypeString,
		Description: "Uername of the user.",
	},
	"password": {
		Type:        framework.TypeString,
		Description: "The password of the user.",
	},
	"project_id": {
		Type:        framework.TypeString,
		Description: "Unique ID of the project.",
	},
	"project_name": {
		Type:        framework.TypeString,
		Description: "Human-readable name of the project.",
	},
	"tenant_id": {
		Type:        framework.TypeString,
		Description: "Unique ID of the tenant.",
	},
	"tenant_name": {
		Type:        framework.TypeString,
		Description: "Human-readable name of the tenant.",
	},
	"user_domain_id": {
		Type:        framework.TypeString,
		Description: "Name of the domain where a user resides.",
	},
	"user_domain_name": {
		Type:        framework.TypeString,
		Description: "Unique ID of the domain where a user resides.",
	},
	"project_domain_id": {
		Type:        framework.TypeString,
		Description: "Unique ID of the domain where a project resides.",
	},
	"project_domain_name": {
		Type:        framework.TypeString,
		Description: "Name of the domain where a project resides.",
	},
	"domain_id": {
		Type:        framework.TypeString,
		Description: "Unique ID of a domain which can be used to identify the source domain of either a user or a project.",
	},
	"domain_name": {
		Type:        framework.TypeString,
		Description: "Name of a domain which can be used to identify the source domain of either a user or a project.",
	},
}

func NewPathConfig(b *OpenStackAuthBackend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config",
			Fields:  configFields,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.updateConfigHandler,
				logical.ReadOperation:   b.readConfigHandler,
				logical.UpdateOperation: b.updateConfigHandler,
			},
			HelpSynopsis:    configSynopsis,
			HelpDescription: configDescription,
		},
	}
}

func (b *OpenStackAuthBackend) readConfigHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	res := &logical.Response{
		Data: map[string]interface{}{
			"auth_url":            config.AuthURL,
			"user_id":             config.UserID,
			"username":            config.Username,
			"project_id":          config.ProjectID,
			"project_name":        config.ProjectName,
			"tenant_id":           config.TenantID,
			"tenant_name":         config.TenantName,
			"user_domain_id":      config.UserDomainID,
			"user_domain_name":    config.UserDomainName,
			"project_domain_id":   config.ProjectDomainID,
			"project_domain_name": config.ProjectDomainName,
			"domain_id":           config.ProjectDomainID,
			"domain_name":         config.ProjectDomainName,
		},
	}

	return res, nil
}

func (b *OpenStackAuthBackend) updateConfigHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var val interface{}
	var ok bool

	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &Config{}
	}

	val, ok = data.GetOk("auth_url")
	if ok {
		config.AuthURL = val.(string)
	}

	val, ok = data.GetOk("token")
	if ok {
		config.Token = val.(string)
	}

	val, ok = data.GetOk("user_id")
	if ok {
		config.UserID = val.(string)
	}

	val, ok = data.GetOk("username")
	if ok {
		config.Username = val.(string)
	}

	val, ok = data.GetOk("password")
	if ok {
		config.Password = val.(string)
	}

	val, ok = data.GetOk("project_id")
	if ok {
		config.ProjectID = val.(string)
	}

	val, ok = data.GetOk("project_name")
	if ok {
		config.ProjectName = val.(string)
	}

	val, ok = data.GetOk("tenant_id")
	if ok {
		config.TenantID = val.(string)
	}

	val, ok = data.GetOk("tenant_name")
	if ok {
		config.TenantName = val.(string)
	}

	val, ok = data.GetOk("user_domain_id")
	if ok {
		config.UserDomainID = val.(string)
	}

	val, ok = data.GetOk("user_domain_name")
	if ok {
		config.UserDomainName = val.(string)
	}

	val, ok = data.GetOk("project_domain_id")
	if ok {
		config.ProjectDomainID = val.(string)
	}

	val, ok = data.GetOk("project_domain_name")
	if ok {
		config.ProjectDomainName = val.(string)
	}

	val, ok = data.GetOk("domain_id")
	if ok {
		config.DomainID = val.(string)
	}

	val, ok = data.GetOk("domain_name")
	if ok {
		config.DomainName = val.(string)
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	b.Close()

	return nil, nil
}
