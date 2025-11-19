// Package geoip provides tests for GeoIP functionality.
package geoip

import (
	"net/netip"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

func TestGeoIP(t *testing.T) {
	// Create a test database content
	testData := `# Test database
16777216,16777471,US
16842752,16843007,AU
`

	// Write test data to a temporary file
	tmpFile, createErr := os.CreateTemp("", "geoip_test_*.csv")
	if createErr != nil {
		t.Fatalf("Failed to create temp file: %v", createErr)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	if _, writeErr := tmpFile.WriteString(testData); writeErr != nil {
		t.Fatalf("Failed to write test data: %v", writeErr)
	}
	_ = tmpFile.Close()

	conf := &Config{
		Logger:       slogutil.NewDiscardLogger(),
		DatabasePath: tmpFile.Name(),
	}

	g, newErr := New(conf)
	if newErr != nil {
		t.Fatalf("Failed to create GeoIP: %v", newErr)
	}
	defer func() { _ = g.Close() }()

	tests := []struct {
		ip       string
		expected string
	}{
		{"1.0.0.1", "US"},   // Within US range
		{"1.1.0.1", "AU"},   // Within AU range
		{"8.8.8.8", ""},     // Not in test ranges
		{"2001:db8::1", ""}, // IPv6 not supported
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip, parseErr := netip.ParseAddr(tt.ip)
			if parseErr != nil {
				t.Fatalf("Invalid IP %s: %v", tt.ip, parseErr)
			}
			country, countryErr := g.Country(ip)
			if countryErr != nil {
				t.Errorf("Country(%s) error: %v", tt.ip, countryErr)
			}
			if country != tt.expected {
				t.Errorf("Country(%s) = %s, expected %s", tt.ip, country, tt.expected)
			}
		})
	}
}
