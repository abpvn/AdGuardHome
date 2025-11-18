// Package geoip provides GeoIP functionality for country lookups.
package geoip

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Interface provides GeoIP functionality.
type Interface interface {
	// Country returns the country code for the given IP address.
	Country(ip netip.Addr) (country string, err error)
	// Close closes the GeoIP database.
	Close() error
}

// Config is the configuration for GeoIP.
type Config struct {
	// Logger is used for logging.
	Logger *slog.Logger

	// DatabasePath is the path to the GeoIP database file.
	DatabasePath string
}

// ipRange represents an IP range with country code.
type ipRange struct {
	start   uint32 // IPv4 as uint32
	end     uint32
	country string
}

// Default implements the Interface using a simple CSV-based database.
type Default struct {
	// ranges is the sorted list of IP ranges.
	ranges []ipRange

	// mu protects the ranges.
	mu sync.RWMutex
}

// New creates a new GeoIP instance.
func New(conf *Config) (*Default, error) {
	data, err := os.ReadFile(conf.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("reading geoip database: %w", err)
	}

	ranges, err := parseDatabase(string(data))
	if err != nil {
		return nil, fmt.Errorf("parsing geoip database: %w", err)
	}

	return &Default{
		ranges: ranges,
	}, nil
}

// parseDatabase parses a simple CSV format: "start_ip,end_ip,country_code"
func parseDatabase(content string) ([]ipRange, error) {
	var ranges []ipRange
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			continue // Skip invalid lines
		}

		start, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			continue
		}
		country := strings.ToUpper(strings.TrimSpace(parts[2]))

		ranges = append(ranges, ipRange{
			start:   uint32(start),
			end:     uint32(end),
			country: country,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Sort ranges by start IP for binary search
	slices.SortFunc(ranges, func(a, b ipRange) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})

	return ranges, nil
}

// Country returns the ISO country code for the given IP.
func (g *Default) Country(ip netip.Addr) (country string, err error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !ip.Is4() {
		return "", nil // Only IPv4 supported for simplicity
	}

	ipUint := ipToUint32(ip)

	// Binary search for the range containing this IP
	for _, r := range g.ranges {
		if ipUint >= r.start && ipUint <= r.end {
			return r.country, nil
		}
	}

	return "", nil
}

// ipToUint32 converts IPv4 address to uint32.
func ipToUint32(ip netip.Addr) uint32 {
	bytes := ip.AsSlice()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

// Close closes the database (no-op for in-memory).
func (g *Default) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ranges = nil
	return nil
}

// Downloader handles downloading and updating the GeoIP database.
type Downloader struct {
	logger *slog.Logger
}

// NewDownloader creates a new downloader.
func NewDownloader(logger *slog.Logger) *Downloader {
	return &Downloader{
		logger: logger,
	}
}

// Download downloads the latest DB-IP country database.
func (d *Downloader) Download(ctx context.Context, databasePath string) error {
	// Try current month first, then previous month
	now := time.Now()
	urls := []string{
		d.generateURL(now),
		d.generateURL(now.AddDate(0, -1, 0)), // Previous month
	}

	for _, url := range urls {
		d.logger.InfoContext(ctx, "attempting to download geoip database", "url", url)

		if err := d.downloadFile(ctx, url, databasePath); err != nil {
			d.logger.WarnContext(ctx, "failed to download from url", "url", url, "error", err)
			continue
		}

		d.logger.InfoContext(ctx, "successfully downloaded geoip database", "url", url)
		return nil
	}

	return fmt.Errorf("failed to download database from all URLs")
}

// generateURL generates the DB-IP download URL for the given time.
func (d *Downloader) generateURL(t time.Time) string {
	year := t.Year()
	month := t.Month()
	return fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%d-%02d.csv.gz", year, month)
}

// downloadFile downloads and extracts a gzipped CSV file.
func (d *Downloader) downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create temp file for download
	tempFile, err := os.CreateTemp(filepath.Dir(destPath), "geoip_download_*.csv")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Decompress and write
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzipReader.Close()

	if _, err := io.Copy(tempFile, gzipReader); err != nil {
		return fmt.Errorf("writing decompressed data: %w", err)
	}

	tempFile.Close()

	// Convert to our format and write to final destination
	if err := d.convertToInternalFormat(tempFile.Name(), destPath); err != nil {
		return fmt.Errorf("converting database format: %w", err)
	}

	return nil
}

// convertToInternalFormat converts DB-IP CSV to our internal format.
func (d *Downloader) convertToInternalFormat(srcPath, destPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening source file: %w", err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating dest file: %w", err)
	}
	defer destFile.Close()

	return d.convertAndWrite(srcFile, destFile)
}

// convertAndWrite reads from src and writes converted data to dest.
func (d *Downloader) convertAndWrite(srcFile *os.File, destFile *os.File) error {
	scanner := bufio.NewScanner(srcFile)
	writer := bufio.NewWriter(destFile)

	// Write header
	if _, err := writer.WriteString("# Converted from DB-IP\n"); err != nil {
		return err
	}

	for scanner.Scan() {
		line, err := d.processLine(scanner.Text())
		if err != nil {
			continue // Skip invalid lines
		}
		if line == "" {
			continue
		}

		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning file: %w", err)
	}

	return writer.Flush()
}

// processLine processes a single line from the DB-IP CSV and returns the converted line.
func (d *Downloader) processLine(text string) (string, error) {
	line := strings.TrimSpace(text)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}

	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid line format")
	}

	// DB-IP format: "start_ip","end_ip","country_code",...
	startIP := strings.Trim(parts[0], `"`)
	endIP := strings.Trim(parts[1], `"`)
	country := strings.Trim(strings.ToUpper(parts[2]), `"`)

	// Convert IPs to uint32
	startUint, err := ipToUint32FromString(startIP)
	if err != nil {
		return "", err
	}
	endUint, err := ipToUint32FromString(endIP)
	if err != nil {
		return "", err
	}

	// Return in our format: start,end,country
	return fmt.Sprintf("%d,%d,%s\n", startUint, endUint, country), nil
}

// ipToUint32FromString converts IP string to uint32.
func ipToUint32FromString(ipStr string) (uint32, error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return 0, err
	}
	if !ip.Is4() {
		return 0, fmt.Errorf("IPv6 not supported")
	}
	return ipToUint32(ip), nil
}
