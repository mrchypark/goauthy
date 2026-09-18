package geoblock

import (
	"errors"
	"net"
	"net/netip"
)

type maxMindLocation struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// Location returns the MaxMind location in the form "alpha2, country[, city]".
func (r *MaxMindReader) Location(ip netip.Addr) (*string, error) {
	if r == nil || r.reader == nil {
		return nil, errors.New("nil MaxMind reader")
	}
	var record maxMindLocation
	if err := r.reader.Lookup(net.IP(ip.AsSlice()), &record); err != nil {
		return nil, err
	}
	if record.Country.ISOCode == "" {
		return nil, nil
	}

	location := formatMaxMindLocation(record)
	return &location, nil
}

func formatMaxMindLocation(record maxMindLocation) string {
	location := record.Country.ISOCode + ", " + record.Country.Names["en"]
	if city, present := record.City.Names["en"]; present {
		location += ", " + city
	}
	return location
}
