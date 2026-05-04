package filtering

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitForClient_Rebuild(t *testing.T) {
	d := newDNSFilter(t)

	clientName := "test-client"
	rules1 := []string{"||example.com^"}
	rules2 := []string{"||example.net^"}

	// First initialization
	d.InitForClient(clientName, nil, nil, rules1)
	
	setts := &Settings{
		ClientName:        clientName,
		FilteringEnabled:  true,
		ProtectionEnabled: true,
		UseGlobalFilters:  false,
		ClientFilters:     []FilterYAML{},
		ClientWhiteListFilters: []FilterYAML{},
	}

	// Check if example.com is blocked
	res1, err := d.CheckHostRules("example.com", 1, setts)
	require.NoError(t, err)
	assert.True(t, res1.Reason.Matched(), "example.com should be blocked by rules1")

	// Second initialization with different rules
	d.InitForClient(clientName, nil, nil, rules2)

	// Check if example.net is blocked
	res2, err := d.CheckHostRules("example.net", 1, setts)
	require.NoError(t, err)
	assert.True(t, res2.Reason.Matched(), "example.net should be blocked after re-init")

	// Check if example.com is NO LONGER blocked
	res3, err := d.CheckHostRules("example.com", 1, setts)
	require.NoError(t, err)
	assert.False(t, res3.Reason.Matched(), "example.com should NOT be blocked after re-init")
}
