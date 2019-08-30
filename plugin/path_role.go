package plugin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleSynopsis = "Register an role with the backend."
const roleDescription = `
A role is required to authenticate with this backend. The role binds
OpenStack instance with token policies and token settings. The bindings, 
token polices and token settings can all be configured using this endpoint.
`

const roleListSynopsis = "Lists all the roles registered with the backend."
const roleListDescription = `
The list will contain the names of the roles.
`

var roleFields map[string]*framework.FieldSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "Name of the role.",
	},
	"policies": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Policies to be set on tokens issued using this role.",
	},
	"ttl": {
		Type:        framework.TypeDurationSecond,
		Default:     0,
		Description: "Duration in seconds after which the issued token should expire. Defaults to 0, in which case the value will fallback to the system/mount defaults.",
	},
	"max_ttl": {
		Type:        framework.TypeDurationSecond,
		Default:     0,
		Description: "The maximum allowed lifetime of tokens issued using this role.",
	},
	"period": {
		Type:        framework.TypeDurationSecond,
		Default:     0,
		Description: "If set, indicates that the token generated using this role should never expire. The token should be renewed within the duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.",
	},
	"metadata_key": {
		Type:        framework.TypeString,
		Default:     "vault-role",
		Description: "The key name of the instance metadata to validate the role specified during authentication. The role name must be specified for the key of metadata of the instance specified here.",
	},
	"auth_period": {
		Type:        framework.TypeDurationSecond,
		Default:     120,
		Description: "The authentication deadline. This is the relative number of seconds since the instance started.",
	},
	"auth_limit": {
		Type:        framework.TypeInt,
		Default:     1,
		Description: "The number of times an instance can try authentication.",
	},
}

func NewPathRole(b *OpenStackAuthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:        fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
			Fields:         roleFields,
			ExistenceCheck: b.checkRoleHandler,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.updateRoleHandler,
				logical.ReadOperation:   b.readRoleHandler,
				logical.UpdateOperation: b.updateRoleHandler,
				logical.DeleteOperation: b.deleteRoleHandler,
			},
			HelpSynopsis:    roleSynopsis,
			HelpDescription: roleDescription,
		},
		{
			Pattern: "role/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.listRoleHandler,
			},
			HelpSynopsis:    roleListSynopsis,
			HelpDescription: roleListDescription,
		},
		{
			Pattern: "roles/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.listRoleHandler,
			},
			HelpSynopsis:    roleListSynopsis,
			HelpDescription: roleListDescription,
		},
	}
}

func (b *OpenStackAuthBackend) checkRoleHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	roleName := strings.ToLower(data.Get("name").(string))
	entry, err := readRole(ctx, req.Storage, roleName)
	return (entry != nil), err
}

func (b *OpenStackAuthBackend) readRoleHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := strings.ToLower(data.Get("name").(string))
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	res := &logical.Response{
		Data: map[string]interface{}{
			"policies":     role.Policies,
			"ttl":          int64(role.TTL / time.Second),
			"max_ttl":      int64(role.MaxTTL / time.Second),
			"period":       int64(role.Period / time.Second),
			"metadata_key": role.MetadataKey,
			"auth_period":  int64(role.AuthPeriod / time.Second),
			"auth_limit":   role.AuthLimit,
		},
	}

	return res, nil
}

func (b *OpenStackAuthBackend) updateRoleHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var val interface{}
	var ok bool

	roleName := strings.ToLower(data.Get("name").(string))
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		role = &Role{Name: roleName}
	}

	val, ok = data.GetOk("policies")
	if ok {
		role.Policies = policyutil.ParsePolicies(val)
	}

	val, ok = data.GetOk("ttl")
	if ok {
		role.TTL = time.Duration(val.(int)) * time.Second
	}

	val, ok = data.GetOk("max_ttl")
	if ok {
		role.MaxTTL = time.Duration(val.(int)) * time.Second
	}

	val, ok = data.GetOk("period")
	if ok {
		role.Period = time.Duration(val.(int)) * time.Second
	}

	val, ok = data.GetOk("metadata_key")
	if ok {
		role.MetadataKey = val.(string)
	}

	val, ok = data.GetOk("auth_period")
	if ok {
		role.AuthPeriod = time.Duration(val.(int)) * time.Second
	}

	val, ok = data.GetOk("auth_limit")
	if ok {
		role.AuthLimit = val.(int)
	}

	warnings, err := role.Validate(b.System())
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role: %v", err)), nil
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", roleName), role)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	res := &logical.Response{
		Warnings: warnings,
	}

	return res, nil
}

func (b *OpenStackAuthBackend) deleteRoleHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := strings.ToLower(data.Get("name").(string))
	if roleName == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	err := req.Storage.Delete(ctx, fmt.Sprintf("role/%s", roleName))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *OpenStackAuthBackend) listRoleHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}
