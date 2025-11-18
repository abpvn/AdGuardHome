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
2130706433,2130706433,LOCAL
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
		{"1.0.0.1", "US"},      // 16777217 -> US
		{"1.1.0.1", "AU"},      // 16842753 -> AU
		{"127.0.0.1", "LOCAL"}, // 2130706433 -> LOCAL
		{"8.8.8.8", ""},        // Not in test ranges
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

func TestGeoIP_InvalidIP(t *testing.T) {
	conf := &Config{
		Logger:       slogutil.NewDiscardLogger(),
		DatabasePath: "testdata/GeoLite2-Country.mmdb",
	}

	g, err := New(conf)
	if err != nil {
		t.Skipf("GeoIP database not available: %v", err)
	}
	defer func() { _ = g.Close() }()

	// Test with invalid IP - should not parse
	_, err = netip.ParseAddr("invalid")
	if err == nil {
		t.Error("Expected parse error for invalid IP string")
	}
}

func TestGeoIP_DatabaseNotFound(t *testing.T) {
	conf := &Config{
		Logger:       slogutil.NewDiscardLogger(),
		DatabasePath: "/nonexistent/path.mmdb",
	}

	_, err := New(conf)
	if err == nil {
		t.Error("Expected error for non-existent database")
	}
}
