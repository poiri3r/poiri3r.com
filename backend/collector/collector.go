package collector

import (
	"time"
	"example.com/db"
)

// ── 타입 정의 ──────────────────────────────────────────

type Summary struct {
	TodayVisitors     int
	MaliciousAttempts int
	BlockedIPs        int
}

type CountryStat struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

type TrafficRatio struct {
	Normal     int `json:"normal"`
	Suspicious int `json:"suspicious"`
}

type BlockReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type AccessEntry struct {
	Time      string `json:"time"`
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    string `json:"status"`
	UserAgent string `json:"user_agent"`
}

type AlertEntry struct {
	CreatedAt     string `json:"created_at"`
	Scenario      string `json:"scenario"`
	SourceIP      string `json:"source_ip"`
	SourceCountry string `json:"source_country"`
	EventsCount   int    `json:"events_count"`
}

type DecisionEntry struct {
	CreatedAt string `json:"created_at"`
	Until     string `json:"until"`
	Scenario  string `json:"scenario"`
	Value     string `json:"value"`
	Type      string `json:"type"`
}

type DashboardData struct {
	VisitorCountries []CountryStat `json:"visitor_countries"`
	AttackCountries  []CountryStat `json:"attack_countries"`
	TrafficRatio     TrafficRatio  `json:"traffic_ratio"`
	BlockReasons     []BlockReason `json:"block_reasons"`
}

// ── 수집 함수 ──────────────────────────────────────────

// Collect: 5분마다 실행, 요약값을 DB에 캐시
func Collect() Summary {
	s := Summary{
		TodayVisitors:     countTodayVisitors(), // nginx.go
		MaliciousAttempts: fetchAlerts(),        // crowdsec.go
		BlockedIPs:        fetchBlockedIPs(),    // crowdsec.go
	}
	saveToCache(s)
	return s
}

// FetchDashboard: 대시보드 그래프용 상세 데이터 (온디맨드)
func FetchDashboard() DashboardData {
	suspiciousIPs := fetchAlertIPs()
	return DashboardData{
		VisitorCountries: fetchVisitorCountries(),       // nginx.go (GeoIP)
		AttackCountries:  fetchAttackCountries(),        // crowdsec.go
		TrafficRatio:     fetchTrafficRatio(suspiciousIPs), // nginx.go + crowdsec.go 크로스
		BlockReasons:     fetchBlockReasons(),           // crowdsec.go
	}
}

// Start: 5분마다 Collect 반복 실행 (main.go에서 goroutine으로 실행)
func Start() {
	for {
		Collect()
		time.Sleep(5 * time.Minute)
	}
}

func saveToCache(s Summary) {
	db.DB.Exec(`
		INSERT INTO visitor_cache (id, today_visitors, malicious_attempts, blocked_ips, updated_at)
		VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			today_visitors     = excluded.today_visitors,
			malicious_attempts = excluded.malicious_attempts,
			blocked_ips        = excluded.blocked_ips,
			updated_at         = excluded.updated_at
	`, s.TodayVisitors, s.MaliciousAttempts, s.BlockedIPs)
}
