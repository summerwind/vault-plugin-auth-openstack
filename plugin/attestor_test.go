package plugin

import (
	"fmt"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
)

func newTestInstance() *servers.Server {
	return &servers.Server{
		ID:         "ef079b0c-e610-4dfb-b1aa-b49f07ac48e5",
		Name:       "test",
		UserID:     "9349aff8be7545ac9d2f1d00999a23cd",
		TenantID:   "fcad67a6189847c4aecfa3c81a05783b",
		HostID:     "29d3c8c896a45aa4c34e52247875d7fefc3d94bbcc9f622b5d204362",
		Status:     "ACTIVE",
		AccessIPv4: "",
		Addresses:  map[string]interface{}{},
		Metadata:   map[string]string{},
		Created:    time.Now(),
		Updated:    time.Now(),
	}
}

func TestAttest(t *testing.T) {
	var tests = []struct {
		diff     int
		limit    int
		attempt  int
		metadata string
		status   string
		addr     string
		tenantID string
		result   bool
	}{
		{0, 2, 1, "test", "ACTIVE", "192.168.1.1", "fcad67a6189847c4aecfa3c81a05783b", true},
		{-130, 2, 1, "test", "ACTIVE", "192.168.1.1", "fcad67a6189847c4aecfa3c81a05783b", false},
		{0, 2, 3, "test", "ACTIVE", "192.168.1.1", "fcad67a6189847c4aecfa3c81a05783b", false},
		{0, 2, 1, "invalid", "ACTIVE", "192.168.1.1", "fcad67a6189847c4aecfa3c81a05783b", false},
		{0, 2, 1, "test", "ERROR", "192.168.1.1", "fcad67a6189847c4aecfa3c81a05783b", false},
		{0, 2, 1, "test", "ACTIVE", "192.168.1.2", "fcad67a6189847c4aecfa3c81a05783b", false},
		{0, 2, 1, "test", "ACTIVE", "192.168.1.1", "invalid", false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	role := &Role{
		Name:        "test",
		Policies:    []string{"test"},
		TTL:         time.Duration(60) * time.Second,
		MaxTTL:      time.Duration(120) * time.Second,
		Period:      time.Duration(120) * time.Second,
		MetadataKey: "vault-role",
		TenantID:    "fcad67a6189847c4aecfa3c81a05783b",
		AuthPeriod:  time.Duration(120) * time.Second,
		AuthLimit:   2,
	}

	for i, test := range tests {
		var err error

		instance := newTestInstance()
		instance.ID = fmt.Sprintf("test%d", i)
		instance.AccessIPv4 = test.addr
		instance.Metadata["vault-role"] = test.metadata
		instance.Status = test.status
		instance.TenantID = test.tenantID
		instance.Created = time.Now().Add(time.Duration(test.diff) * time.Second)

		for i := 0; i < test.attempt; i++ {
			err = attestor.Attest(instance, role, []string{"192.168.1.1"})
		}
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestMetadata(t *testing.T) {
	var tests = []struct {
		key    string
		val    string
		result bool
	}{
		{"vault-role", "test", true},
		{"invalid", "test", false},
		{"vault-role", "invalid", false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	for _, test := range tests {
		instance := newTestInstance()
		instance.Metadata[test.key] = test.val

		err := attestor.AttestMetadata(instance, "vault-role", "test")
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestStatus(t *testing.T) {
	var tests = []struct {
		status string
		result bool
	}{
		{"ACTIVE", true},
		{"STOPPED", false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	for _, test := range tests {
		instance := newTestInstance()
		instance.Status = test.status

		err := attestor.AttestStatus(instance)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestAddr(t *testing.T) {
	var tests = []struct {
		access    string
		addresses []string
		request   []string
		result    bool
	}{
		{"192.168.1.1", []string{"192.168.1.1"}, []string{"192.168.1.1"}, true},
		{"192.168.1.1", []string{}, []string{"192.168.1.1"}, true},
		{"", []string{"192.168.1.1"}, []string{"192.168.1.1"}, true},
		{"", []string{"192.168.1.1", "192.168.1.2"}, []string{"192.168.1.1"}, true},
		{"192.168.1.2", []string{"192.168.1.2"}, []string{"192.168.1.1"}, false},
		{"192.168.1.2", []string{}, []string{"192.168.1.1"}, false},
		{"", []string{"192.168.1.2"}, []string{"192.168.1.1"}, false},
		{"", []string{"192.168.1.2", "192.168.1.3"}, []string{"192.168.1.1"}, false},
		// simulate proxy, correct IP only in additional request addresses
		{"192.168.1.1", []string{"192.168.1.1"}, []string{"192.168.2.1", "192.168.1.1"}, true},
		{"192.168.1.1", []string{}, []string{"192.168.2.1", "192.168.1.1"}, true},
		{"", []string{"192.168.1.1"}, []string{"192.168.2.1", "192.168.1.1"}, true},
		{"", []string{"192.168.1.1", "192.168.1.2"}, []string{"192.168.2.1", "192.168.1.1"}, true},
		{"192.168.1.2", []string{"192.168.1.2"}, []string{"192.168.2.1", "192.168.1.1"}, false},
		{"192.168.1.2", []string{}, []string{"192.168.2.1", "192.168.1.1"}, false},
		{"", []string{"192.168.1.2"}, []string{"192.168.2.1", "192.168.1.1"}, false},
		{"", []string{"192.168.1.2", "192.168.1.3"}, []string{"192.168.2.1", "192.168.1.1"}, false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	for _, test := range tests {
		instance := newTestInstance()
		instance.AccessIPv4 = test.access
		if len(test.addresses) > 0 {
			addresses := []interface{}{}
			for _, addr := range test.addresses {
				addresses = append(addresses, map[string]interface{}{
					"OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:9e:89:be",
					"OS-EXT-IPS:type":         "fixed",
					"version":                 float64(4),
					"addr":                    addr,
				})
			}
			instance.Addresses = map[string]interface{}{
				"private": addresses,
			}
		}

		err := attestor.AttestAddr(instance, test.request)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestTenantID(t *testing.T) {
	var tests = []struct {
		tenantID string
		result   bool
	}{
		{"", true},
		{"fcad67a6189847c4aecfa3c81a05783b", true},
		{"invalid", false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	for _, test := range tests {
		instance := newTestInstance()

		err := attestor.AttestTenantID(instance, test.tenantID)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestUserID(t *testing.T) {
	var tests = []struct {
		userID string
		result bool
	}{
		{"", true},
		{"9349aff8be7545ac9d2f1d00999a23cd", true},
		{"invalid", false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	for _, test := range tests {
		instance := newTestInstance()

		err := attestor.AttestUserID(instance, test.userID)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestVerifyAuthPeriod(t *testing.T) {
	var tests = []struct {
		diff   int
		period int
		result bool
	}{
		{0, 120, true},
		{-119, 120, true},
		{-120, 120, false},
		{-121, 120, false},
	}

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	for _, test := range tests {
		instance := newTestInstance()
		instance.Created = time.Now().Add(time.Duration(test.diff) * time.Second)
		period := time.Duration(test.period) * time.Second

		_, err := attestor.VerifyAuthPeriod(instance, period)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestVerifyAuthLimit(t *testing.T) {
	instance := newTestInstance()
	limit := 2
	deadline := time.Now().Add(30 * time.Second)

	_, storage := newTestBackend(t)
	attestor := NewAttestor(storage)

	count, err := attestor.VerifyAuthLimit(instance, limit, deadline)
	if count != 1 || err != nil {
		t.Errorf("unexpected result: [%d] %v", count, err)
	}

	count, err = attestor.VerifyAuthLimit(instance, limit, deadline)
	if count != 2 || err != nil {
		t.Errorf("unexpected result: [%d] %v", count, err)
	}

	count, err = attestor.VerifyAuthLimit(instance, limit, deadline)
	if count != 3 || err == nil {
		t.Errorf("unexpected result: [%d]", count)
	}
}
