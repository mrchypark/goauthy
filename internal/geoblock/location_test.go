package geoblock

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaxMindReaderLocationUsesExistingFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, countryTestDB, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenMaxMind(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	location, err := reader.Location(netip.MustParseAddr("2001:220::1"))
	if err != nil {
		t.Fatal(err)
	}
	if location == nil || !strings.HasPrefix(*location, "KR, ") {
		t.Fatalf("Location()=%v; want KR country result", location)
	}
}

func TestMaxMindReaderLocationUnknownIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, countryTestDB, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenMaxMind(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	location, err := reader.Location(netip.MustParseAddr("214.1.1.1"))
	if err != nil || location != nil {
		t.Fatalf("Location()=%v, %v; want nil, nil", location, err)
	}
}

func TestMaxMindReaderLocationNilReader(t *testing.T) {
	var reader *MaxMindReader
	location, err := reader.Location(netip.MustParseAddr("2001:db8::1"))
	if location != nil || err == nil || err.Error() != "nil MaxMind reader" {
		t.Fatalf("Location()=%v, %v; want nil reader error", location, err)
	}
}

func TestMaxMindLocationEnglishNamesFallbacks(t *testing.T) {
	t.Run("present empty city", func(t *testing.T) {
		record := maxMindLocation{}
		record.Country.ISOCode = "KR"
		record.Country.Names = map[string]string{"en": "South Korea"}
		record.City.Names = map[string]string{"en": ""}
		if got := formatMaxMindLocation(record); got != "KR, South Korea, " {
			t.Fatalf("formatted location=%q", got)
		}
	})
	for name, test := range map[string]struct {
		code, country, city string
		want                string
	}{
		"country and city":     {code: "KR", country: "South Korea", city: "Seoul", want: "KR, South Korea, Seoul"},
		"missing country name": {code: "KR", city: "Seoul", want: "KR, , Seoul"},
		"missing city name":    {code: "KR", country: "South Korea", want: "KR, South Korea"},
	} {
		t.Run(name, func(t *testing.T) {
			record := maxMindLocation{}
			record.Country.ISOCode = test.code
			record.Country.Names = map[string]string{}
			record.City.Names = map[string]string{}
			if test.country != "" {
				record.Country.Names["en"] = test.country
			}
			if test.city != "" {
				record.City.Names["en"] = test.city
			}
			got := formatMaxMindLocation(record)
			if got != test.want {
				t.Fatalf("formatted location=%q want %q", got, test.want)
			}
		})
	}
}
