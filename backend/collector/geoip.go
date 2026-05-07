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
			// Country DB 없으면 City DB로 폴백 (둘 다 국가 정보 포함)
			path = "/var/lib/crowdsec/data/GeoLite2-City.mmdb"
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
	// City DB는 City() 메서드로 읽고 Country.IsoCode 추출
	record, err := db.City(parsed)
	if err != nil || record.Country.IsoCode == "" {
		return ""
	}
	return record.Country.IsoCode
}
