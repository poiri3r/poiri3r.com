package collector

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func crowdsecDBPath() string {
	if p := os.Getenv("CROWDSEC_DB_PATH"); p != "" {
		return p
	}
	return "/var/lib/crowdsec/data/crowdsec.db"
}

func openCrowdsecDB() (*sql.DB, error) {
	return sql.Open("sqlite3", crowdsecDBPath()+"?mode=ro")
}

// 실제 공격 탐지 수 (커뮤니티 IP 업데이트 제외)
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

// 현재 차단된 IP 수
func fetchBlockedIPs() int {
	db, err := openCrowdsecDB()
	if err != nil {
		return 0
	}
	defer db.Close()

	var count int
	db.QueryRow(`SELECT COUNT(*) FROM decisions`).Scan(&count)
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

// 공격자 국가 분포 (상위 10개)
func fetchAttackCountries() []CountryStat {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT source_country, COUNT(*) as cnt
		FROM alerts
		WHERE source_ip != '' AND source_country != ''
		GROUP BY source_country
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var stats []CountryStat
	for rows.Next() {
		var s CountryStat
		rows.Scan(&s.Country, &s.Count)
		stats = append(stats, s)
	}
	return stats
}

// 차단 이유 분포 (상위 10개)
func fetchBlockReasons() []BlockReason {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT scenario, COUNT(*) as cnt
		FROM decisions
		GROUP BY scenario
		ORDER BY cnt DESC
		LIMIT 10
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

// CrowdSec 알럿 상세 목록
func FetchAlertList(limit int) []AlertEntry {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT created_at, scenario, source_ip, source_country, events_count
		FROM alerts
		WHERE source_ip != ''
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []AlertEntry
	for rows.Next() {
		var e AlertEntry
		rows.Scan(&e.CreatedAt, &e.Scenario, &e.SourceIP, &e.SourceCountry, &e.EventsCount)
		entries = append(entries, e)
	}
	return entries
}

// CrowdSec 차단 목록
func FetchDecisionList(limit int) []DecisionEntry {
	db, err := openCrowdsecDB()
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT created_at, until, scenario, value, type
		FROM decisions
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []DecisionEntry
	for rows.Next() {
		var e DecisionEntry
		rows.Scan(&e.CreatedAt, &e.Until, &e.Scenario, &e.Value, &e.Type)
		entries = append(entries, e)
	}
	return entries
}
