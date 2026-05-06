package collector

import (
	"net"
	"os"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDB   *geoip2.Reader
	geoOnce sync.Once
)

func getGeoDB() *geoip2.Reader {
	geoOnce.Do(func() {
		path := os.Getenv("GEOIP_DB_PATH")
		if path == "" {
			// CrowdSec이 내부적으로 사용하는 GeoLite2 기본 경로
			path = "/var/lib/crowdsec/data/GeoLite2-Country.mmdb"
		}
		db, err := geoip2.Open(path)
		if err != nil {
			return
		}
		geoDB = db
	})
	return geoDB
}

func lookupCountry(ip string) string {
	db := getGeoDB()
	if db == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	record, err := db.Country(parsed)
	if err != nil || record.Country.IsoCode == "" {
		return "Unknown"
	}
	return record.Country.IsoCode
}
