package plugin

import (
	"context"
	"errors"
	"time"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
)

type address struct {
	Version int    `mapstructure:"version"`
	Address string `mapstructure:"addr"`
}

type Attestor struct {
	storage logical.Storage
}

// NewAttestor returns new attestor.
func NewAttestor(s logical.Storage) *Attestor {
	return &Attestor{storage: s}
}

// Attest is used to attest a OpenStack instance based on binded role and IP address.
func (at *Attestor) Attest(instance *servers.Server, role *Role, addrs []string) error {
	deadline, err := at.VerifyAuthPeriod(instance, role.AuthPeriod)
	if err != nil {
		return err
	}

	_, err = at.VerifyAuthLimit(instance, role.AuthLimit, deadline)
	if err != nil {
		return err
	}

	err = at.AttestAddr(instance, addrs)
	if err != nil {
		return err
	}

	err = at.AttestStatus(instance)
	if err != nil {
		return err
	}

	err = at.AttestMetadata(instance, role.MetadataKey, role.Name)
	if err != nil {
		return err
	}

	err = at.AttestTenantID(instance, role.TenantID)
	if err != nil {
		return err
	}

	err = at.AttestUserID(instance, role.UserID)
	if err != nil {
		return err
	}

	return nil
}

// AttestMetadata is used to attest a OpenStack instance metadata.
func (at *Attestor) AttestMetadata(instance *servers.Server, metadataKey string, roleName string) error {
	val, ok := instance.Metadata[metadataKey]
	if !ok {
		return errors.New("metadata key not found")
	}

	if val != roleName {
		return errors.New("metadata role name mismatched")
	}

	return nil
}

// AttestStatus is used to attest the status of OpenStack instance.
func (at *Attestor) AttestStatus(instance *servers.Server) error {
	if instance.Status != "ACTIVE" {
		return errors.New("instance is not active")
	}

	return nil
}

// AttestAddr is used to attest the IP address of OpenStack instance
// with source IP address.
func (at *Attestor) AttestAddr(instance *servers.Server, addrs []string) error {
	var instanceAddresses map[string][]address

	for _, addr := range addrs {
		if instance.AccessIPv4 == addr {
			return nil
		}
		if instance.AccessIPv6 == addr {
			return nil
		}

		err := mapstructure.Decode(instance.Addresses, &instanceAddresses)
		if err != nil {
			return err
		}

		for _, instAddrs := range instanceAddresses {
			for _, val := range instAddrs {
				if val.Address == addr {
					return nil
				}
			}
		}
	}

	return errors.New("address mismatched")
}

// AttestTenantID is used to attest the tenant ID of OpenStack instance.
func (at *Attestor) AttestTenantID(instance *servers.Server, tenantID string) error {
	if tenantID == "" {
		return nil
	}

	if instance.TenantID != tenantID {
		return errors.New("tenant ID mismatched")
	}

	return nil
}

// AttestUserID is used to attest the user ID of OpenStack instance.
func (at *Attestor) AttestUserID(instance *servers.Server, userID string) error {
	if userID == "" {
		return nil
	}

	if instance.UserID != userID {
		return errors.New("user ID mismatched")
	}

	return nil
}

// VerifyAuthPeriod is used to verify the deadline of authentication.
// The deadline is calculated by the create date of OpenStack instance and
// the authentication period specified by a binded role.
func (at *Attestor) VerifyAuthPeriod(instance *servers.Server, period time.Duration) (time.Time, error) {
	deadline := instance.Created.Add(period)
	if time.Now().After(deadline) {
		return deadline, errors.New("authentication deadline exceeded")
	}

	return deadline, nil
}

// VerifyAuthLimit is used to verify the number of attempts of authentication.
// The limit of authentication is specified by a binded role.
func (at *Attestor) VerifyAuthLimit(instance *servers.Server, limit int, deadline time.Time) (int, error) {
	ctx := context.Background()

	attempt, err := readAuthAttempt(ctx, at.storage, instance.ID)
	if err != nil {
		return 0, err
	}

	if attempt == nil {
		attempt = &AuthAttempt{
			Name:     instance.ID,
			Deadline: deadline,
			Count:    0,
		}
	}

	attempt.Count = attempt.Count + 1

	err = updateAuthAttempt(ctx, at.storage, attempt)
	if err != nil {
		return attempt.Count, err
	}

	if attempt.Count > limit {
		return attempt.Count, errors.New("too many authentication failures")
	}

	return attempt.Count, nil
}
