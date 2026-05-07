package collector

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// crowdsecDB가 환경변수로 등록되어 있으면 해당 값 반환, 없으면 기본 경로
func crowdsecDBPath() string {
	if p := os.Getenv("CROWDSEC_DB_PATH"); p != "" {
		return p
	}
	return "/var/lib/crowdsec/data/crowdsec.db"
}

// crowdsecDB를 readonly로 열기
func openCrowdsecDB() (*sql.DB, error) {
	return sql.Open("sqlite3", crowdsecDBPath()+"?mode=ro")
}

// 실제 공격 탐지 수 (커뮤니티 블록리스트 제외)
func fetchAlerts() int {
	db, err := openCrowdsecDB()
	if err != nil {
		return 0
	}
	defer db.Close()

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE source_ip != ''`).Scan(&count)
	return count
}

// 로컬에서 직접 차단한 IP 수 (CAPI 커뮤니티 블록리스트 제외)
func fetchBlockedIPs() int {
	db, err := openCrowdsecDB()
	if err != nil {
		return 0
	}
	defer db.Close()

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM decisions WHERE origin = 'crowdsec'`).Scan(&count)
	return count
}

// nginx 로그와 크로스 레퍼런스용 공격 IP 집합
func fetchAlertIPs() map[string]struct{} {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`SELECT DISTINCT source_ip FROM alerts WHERE source_ip != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	ips := make(map[string]struct{})
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		ips[ip] = struct{}{}
	}
	return ips
}

// 공격자 국가 분포 — alerts의 source_country + 로컬 decisions IP GeoIP 조회 합산 (상위 10개)
func fetchAttackCountries() []CountryStat {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	counts := make(map[string]int)

	// 1. alerts 테이블의 source_country — rows 다 읽은 후 명시적으로 닫기
	rows, err := db.Query(`
		SELECT source_country, COUNT(*) as cnt
		FROM alerts
		WHERE source_ip != '' AND source_country != ''
		GROUP BY source_country
		ORDER BY cnt DESC
		LIMIT 5
	`)
	if err == nil {
		for rows.Next() {
			var country string
			var cnt int
			rows.Scan(&country, &cnt)
			counts[country] += cnt
		}
		rows.Close() // defer 대신 명시적 close (SQLite 동시 쿼리 방지)
	}

	// 2. 로컬 decisions IP를 GeoIP로 조회해서 합산 — 먼저 IP 목록 수집
	var decisionIPs []string
	ipRows, err := db.Query(`SELECT DISTINCT value FROM decisions WHERE origin = 'crowdsec'`)
	if err == nil {
		for ipRows.Next() {
			var ip string
			ipRows.Scan(&ip)
			decisionIPs = append(decisionIPs, ip)
		}
		ipRows.Close()
	}
	for _, ip := range decisionIPs {
		country := lookupCountry(ip)
		if country != "" {
			counts[country]++
		}
	}

	return sortedCountryStats(counts, 5)
}

// 차단 이유 분포 — 로컬 차단만 (CAPI 제외), 상위 10개
func fetchBlockReasons() []BlockReason {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT scenario, COUNT(*) as cnt
		FROM decisions
		WHERE origin = 'crowdsec'
		GROUP BY scenario
		ORDER BY cnt DESC
		LIMIT 5
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reasons []BlockReason
	for rows.Next() {
		var r BlockReason
		rows.Scan(&r.Reason, &r.Count)
		reasons = append(reasons, r)
	}
	return reasons
}

// CrowdSec 알림 상세 목록
func FetchAlertList(limit int) []AlertEntry {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT a.created_at, a.scenario, a.source_ip, a.source_country, a.events_count,
		       COALESCE((SELECT d.type FROM decisions d WHERE d.value = a.source_ip AND d.origin = 'crowdsec' LIMIT 1), '—') as action
		FROM alerts a
		WHERE a.source_ip != ''
		ORDER BY a.created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []AlertEntry
	for rows.Next() {
		var e AlertEntry
		rows.Scan(&e.CreatedAt, &e.Scenario, &e.SourceIP, &e.SourceCountry, &e.EventsCount, &e.Action)
		entries = append(entries, e)
	}
	return entries
}

