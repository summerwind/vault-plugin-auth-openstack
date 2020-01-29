package plugin

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const loginSynopsis = "Authenticates OpenStack instance with Vault."
const loginDescription = `
Authenticates OpenStack instance.
`

var loginFields map[string]*framework.FieldSchema = map[string]*framework.FieldSchema{
	"instance_id": {
		Type:        framework.TypeString,
		Description: "ID of the instance.",
	},
	"role": {
		Type:        framework.TypeString,
		Description: "Name of the role.",
	},
}

func NewPathLogin(b *OpenStackAuthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "login$",
			Fields:  loginFields,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation:         b.loginHandler,
				logical.AliasLookaheadOperation: b.loginHandler,
			},
			HelpSynopsis:    loginSynopsis,
			HelpDescription: loginDescription,
		},
	}
}

func (b *OpenStackAuthBackend) loginHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var val interface{}
	var ok bool

	val, ok = data.GetOk("instance_id")
	if !ok {
		return logical.ErrorResponse("instance_id required"), nil
	}
	instanceID := val.(string)

	val, ok = data.GetOk("role")
	if !ok {
		return logical.ErrorResponse("role required"), nil
	}
	roleName := val.(string)

	b.Logger().Info("login attempt", "instance_id", instanceID, "role", roleName)

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role: %v", err)), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		msg := "openstack client error"
		b.Logger().Error(msg, "error", err)
		return nil, fmt.Errorf("%s: %v", msg, err)
	}

	instance, err := servers.Get(client, instanceID).Extract()
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to find instance: %v", err)), nil
	}

	attestor := NewAttestor(req.Storage)
	if err != nil {
		msg := "attestor error"
		b.Logger().Error(msg, "error", err)
		return nil, fmt.Errorf("%s: %v", msg, err)
	}

	err = attestor.Attest(instance, role, req.Connection.RemoteAddr)
	if err != nil {
		b.Logger().Info("attestation failed", "error", err)
		return logical.ErrorResponse(fmt.Sprintf("failed to login: %v", err)), nil
	}

	res := &logical.Response{}

	if req.Operation == logical.AliasLookaheadOperation {
		res.Auth = &logical.Auth{
			Alias: &logical.Alias{
				Name: instance.ID,
			},
		}
	}

	res.Auth = &logical.Auth{
		Period: role.Period,
		Alias: &logical.Alias{
			Name: instance.ID,
		},
		Policies: role.Policies,
		Metadata: map[string]string{
			"role": roleName,
		},
		DisplayName: instance.Name,
		LeaseOptions: logical.LeaseOptions{
			Renewable: true,
			TTL:       role.TTL,
			MaxTTL:    role.MaxTTL,
		},
	}

	return res, nil
}

func (b *OpenStackAuthBackend) authRenewHandler(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.Auth.Alias == nil {
		return logical.ErrorResponse("instance ID associated with token is invalid"), nil
	}

	instanceID := req.Auth.Alias.Name
	if instanceID == "" {
		return logical.ErrorResponse("instance ID associated with token is invalid"), nil
	}

	roleName := req.Auth.Metadata["role"]
	if roleName == "" {
		return logical.ErrorResponse("role name associated with token is invalid"), nil
	}

	role, err := readRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' no longer exists", roleName)), nil
	}

	if !policyutil.EquivalentPolicies(role.Policies, req.Auth.Policies) {
		return logical.ErrorResponse(fmt.Sprintf("policies on role '%s' have changed, cannot renew", roleName)), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		msg := "openstack client error"
		b.Logger().Error(msg, "error", err)
		return nil, fmt.Errorf("%s: %v", msg, err)
	}

	instance, err := servers.Get(client, instanceID).Extract()
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to find instance: %v", err)), nil
	}

	attestor := NewAttestor(req.Storage)
	if err != nil {
		msg := "attestor error"
		b.Logger().Error(msg, "error", err)
		return nil, fmt.Errorf("%s: %v", msg, err)
	}

	err = attestor.AttestMetadata(instance, role.MetadataKey, role.Name)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to renew: %v", err)), nil
	}

	err = attestor.AttestAddr(instance, req.Connection.RemoteAddr)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to renew: %v", err)), nil
	}

	res := &logical.Response{Auth: req.Auth}
	res.Auth.Period = role.Period
	res.Auth.TTL = role.TTL
	res.Auth.MaxTTL = role.MaxTTL

	return res, nil
}
