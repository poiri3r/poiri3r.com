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
	//Do안의 코드는 프로그램 전체 실행 중 딱 한번만 실행(리소스 절약)
	//geoip DB는 크기가 커서 리소스 절약을 위해
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
//geoDB를 가져와서 국가를 찾는 함수
func lookupCountry(ip string) string {
	db := getGeoDB()
	if db == nil {
		return ""
	}
	//ip를 문자열에서 IP타입으로 변경
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
