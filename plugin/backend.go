package plugin

import (
	"context"
	"fmt"
	"sync"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/utils/openstack/clientconfig"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	help = "The OpenStack backend plugin allows authentication for OpenStack instances."
)

type OpenStackAuthBackend struct {
	*framework.Backend
	client      *gophercloud.ServiceClient
	clientMutex sync.RWMutex
}

func NewBackend() *OpenStackAuthBackend {
	b := &OpenStackAuthBackend{}

	b.Backend = &framework.Backend{
		BackendType:  logical.TypeCredential,
		Invalidate:   b.invalidateHandler,
		PeriodicFunc: b.periodicHandler,
		AuthRenew:    b.authRenewHandler,
		Help:         help,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
			SealWrapStorage: []string{"config"},
		},
		Paths: framework.PathAppend(NewPathConfig(b), NewPathRole(b), NewPathLogin(b)),
	}

	return b
}

func (b *OpenStackAuthBackend) Close() {
	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	b.client = nil
}

func (b *OpenStackAuthBackend) getClient(ctx context.Context, s logical.Storage) (*gophercloud.ServiceClient, error) {
	b.clientMutex.RLock()
	if b.client != nil {
		defer b.clientMutex.RUnlock()
		return b.client, nil
	}
	b.clientMutex.RUnlock()

	b.clientMutex.Lock()
	defer b.clientMutex.Unlock()

	config, err := readConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	opts := &clientconfig.ClientOpts{
		AuthInfo: &clientconfig.AuthInfo{
			AuthURL:           config.AuthURL,
			Token:             config.Token,
			UserID:            config.UserID,
			Username:          config.Username,
			Password:          config.Password,
			ProjectID:         config.ProjectID,
			ProjectName:       config.ProjectName,
			UserDomainID:      config.UserDomainID,
			UserDomainName:    config.UserDomainName,
			ProjectDomainID:   config.ProjectDomainID,
			ProjectDomainName: config.ProjectDomainName,
			DomainID:          config.DomainID,
			DomainName:        config.DomainName,
		},
	}

	if config.TenantID != "" {
		opts.AuthInfo.ProjectID = config.TenantID
	}
	if config.TenantName != "" {
		opts.AuthInfo.ProjectName = config.TenantName
	}

	authOpts, err := clientconfig.AuthOptions(opts)
	if err != nil {
		return nil, err
	}
	authOpts.AllowReauth = true

	provider, err := openstack.AuthenticatedClient(*authOpts)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewComputeV2(provider, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	b.client = client

	return b.client, nil
}

func (b *OpenStackAuthBackend) invalidateHandler(_ context.Context, key string) {
	switch key {
	case "config":
		b.Close()
	}
}

func (b *OpenStackAuthBackend) periodicHandler(ctx context.Context, req *logical.Request) error {
	count, err := cleanupAuthAttempt(ctx, req.Storage)
	if err != nil {
		return err
	}

	b.Logger().Info(fmt.Sprintf("%d expired auth attempts has been removed", count))

	return nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := NewBackend()
	err := b.Setup(ctx, conf)
	if err != nil {
		return nil, err
	}

	return b, nil
}
