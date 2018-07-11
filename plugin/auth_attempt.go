package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
)

type AuthAttempt struct {
	Name     string    `json:"name" structs:"name" mapstructure:"name"`
	Deadline time.Time `json:"deadline" structs:"deadline" mapstructure:"deadline"`
	Count    int       `json:"count" structs:"count" mapstructure:"count"`
}

func readAuthAttempt(ctx context.Context, s logical.Storage, name string) (*AuthAttempt, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("auth_attempt/%s", name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	attempt := &AuthAttempt{}
	err = entry.DecodeJSON(attempt)
	if err != nil {
		return nil, err
	}

	return attempt, nil
}

func updateAuthAttempt(ctx context.Context, s logical.Storage, attempt *AuthAttempt) error {
	if attempt.Name == "" {
		return errors.New("invalid attempt name")
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("auth_attempt/%s", attempt.Name), attempt)
	if err != nil {
		return err
	}

	err = s.Put(ctx, entry)
	if err != nil {
		return err
	}

	return nil
}

func cleanupAuthAttempt(ctx context.Context, s logical.Storage) (int, error) {
	count := 0

	keys, err := s.List(ctx, "auth_attempt/")
	if err != nil {
		return 0, err
	}

	for _, key := range keys {
		attempt, err := readAuthAttempt(ctx, s, key)
		if err != nil {
			return 0, err
		}

		if time.Now().After(attempt.Deadline) {
			err := s.Delete(ctx, fmt.Sprintf("auth_attempt/%s", key))
			if err != nil {
				return 0, err
			}
			count += 1
		}
	}

	return count, nil
}
