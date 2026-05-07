package collector

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"time"
)

func nginxLogPath() string {
	if p := os.Getenv("NGINX_LOG_PATH"); p != "" {
		return p
	}
	return "/var/log/nginx/access.log"
}

func countTodayVisitors() int {
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return 0
	}
	defer f.Close()

	today := time.Now().Format("02/Jan/2006")
	unique := make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, today) {
			continue
		}
		ip := strings.SplitN(line, " ", 2)[0]
		unique[ip] = struct{}{}
	}
	return len(unique)
}

// 전체 방문자 국가 분포 (GeoIP, 상위 10개)
func fetchVisitorCountries() []CountryStat {
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return nil
	}
	defer f.Close()

	ipSeen := make(map[string]struct{})
	countryCounts := make(map[string]int)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		ip := strings.SplitN(line, " ", 2)[0]
		if _, seen := ipSeen[ip]; seen {
			continue
		}
		ipSeen[ip] = struct{}{}
		country := lookupCountry(ip)
		if country != "" {
			countryCounts[country]++
		}
	}
	return sortedCountryStats(countryCounts, 5)
}

// 오늘 정상/이상 트래픽 비율 (CrowdSec 탐지 IP 기준)
func fetchTrafficRatio(suspiciousIPs map[string]struct{}) TrafficRatio {
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return TrafficRatio{}
	}
	defer f.Close()

	today := time.Now().Format("02/Jan/2006")
	var normal, suspicious int

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, today) {
			continue
		}
		ip := strings.SplitN(line, " ", 2)[0]
		if _, isSuspicious := suspiciousIPs[ip]; isSuspicious {
			suspicious++
		} else {
			normal++
		}
	}
	return TrafficRatio{Normal: normal, Suspicious: suspicious}
}

func sortedCountryStats(counts map[string]int, limit int) []CountryStat {
	stats := make([]CountryStat, 0, len(counts))
	for country, count := range counts {
		stats = append(stats, CountryStat{Country: country, Count: count})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})
	if len(stats) > limit {
		stats = stats[:limit]
	}
	return stats
}

// ParseRecentLogs returns the last n entries from nginx access log
func ParseRecentLogs(n int) []AccessEntry {
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	// 최신순으로 뒤집은 뒤 IP별 최대 3개만 포함
	raw := make([]AccessEntry, 0, len(lines))
	for _, line := range lines {
		if e, ok := parseNginxLine(line); ok {
			raw = append(raw, e)
		}
	}
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}

	ipCount := make(map[string]int)
	entries := make([]AccessEntry, 0, len(raw))
	for _, e := range raw {
		if ipCount[e.IP] < 3 {
			entries = append(entries, e)
			ipCount[e.IP]++
		}
	}
	return entries
}

func parseNginxLine(line string) (AccessEntry, bool) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return AccessEntry{}, false
	}
	ip := parts[0]

	timeStart := strings.Index(line, "[")
	timeEnd := strings.Index(line, "]")
	if timeStart < 0 || timeEnd < 0 {
		return AccessEntry{}, false
	}
	rawTime := line[timeStart+1 : timeEnd]

	reqStart := strings.Index(line[timeEnd:], `"`)
	reqEnd := strings.Index(line[timeEnd+reqStart+1:], `"`)
	if reqStart < 0 || reqEnd < 0 {
		return AccessEntry{}, false
	}
	req := line[timeEnd+reqStart+1 : timeEnd+reqStart+1+reqEnd]
	reqParts := strings.Fields(req)
	method, path := "", ""
	if len(reqParts) >= 2 {
		method = reqParts[0]
		path = reqParts[1]
	}

	// 유효한 HTTP 메서드가 아니면 제외
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
	}
	if !validMethods[method] {
		return AccessEntry{}, false
	}

	after := strings.Fields(line[timeEnd+reqStart+1+reqEnd+1:])
	status := ""
	if len(after) >= 2 {
		status = after[1]
	}

	uaStart := strings.LastIndex(line, `"`)
	uaEnd := strings.LastIndex(line[:uaStart], `"`)
	ua := ""
	if uaStart > 0 && uaEnd > 0 && uaStart > uaEnd {
		ua = line[uaEnd+1 : uaStart]
	}

	return AccessEntry{
		Time:      rawTime,
		IP:        ip,
		Method:    method,
		Path:      path,
		Status:    status,
		UserAgent: ua,
	}, true
}
