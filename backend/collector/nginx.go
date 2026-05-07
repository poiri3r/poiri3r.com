package collector

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"time"
)
//http 매서드 목록
var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"HEAD": true, "OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
}

//nginx log 경로
func nginxLogPath() string {
	if p := os.Getenv("NGINX_LOG_PATH"); p != "" {
		return p
	}
	return "/var/log/nginx/access.log"
}
//하루 방문자 세기
func countTodayVisitors() int {
	//이건 로그 기록을 읽어서
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return 0
	}
	defer f.Close()
	//타임 포맷
	today := time.Now().Format("02/Jan/2006")
	unique := make(map[string]struct{})

	scanner := bufio.NewScanner(f)
	//scanner의 퍼버는 1MB
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		//오늘 날자인지 확인
		if !strings.Contains(line, today) {
			continue
		}
		//IP추출후 집합헤 추가
		ip := strings.SplitN(line, " ", 2)[0]
		unique[ip] = struct{}{}
	}
	//오늘 접속한 고유 ip개수 반환
	return len(unique)
}

// 전체 방문자 국가 분포 (GeoIP, 상위 10개)
func fetchVisitorCountries() []CountryStat {
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	//이미 처리된 ip를 담은 ipSeen과 국가별 방문자수를 담은 countryCounts
	ipSeen := make(map[string]struct{})
	countryCounts := make(map[string]int)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		ip := strings.SplitN(line, " ", 2)[0]
		//이미 본적 있는 ip면 스킵
		if _, seen := ipSeen[ip]; seen {
			continue
		}
		//본 적 없으면 geoIP로 조회해서 추가
		ipSeen[ip] = struct{}{}
		country := lookupCountry(ip)
		if country != "" {
			countryCounts[country]++
		}
	}
	return sortedCountryStats(countryCounts, 5)
}

// 오늘 정상/이상 트래픽 비율 (CrowdSec 탐지 IP 기준)
// nginx로그에서 일반 로그는 normal ++ crowdsec에 있는 ip는 suspicious++
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

//프론트엔드에서 차트에 사용하기 위해 순서를 정렬해서 보냄
func sortedCountryStats(counts map[string]int, limit int) []CountryStat {
	//map을 슬라이스형태로 변환
	stats := make([]CountryStat, 0, len(counts))
	for country, count := range counts {
		stats = append(stats, CountryStat{Country: country, Count: count})
	}
	//슬라이스 정렬
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})
	//상위 n개만 자르기
	if len(stats) > limit {
		stats = stats[:limit]
	}
	return stats
}

// 최근 로그 파싱
//nginx에서 줄을 읽어서 파싱하고 ParseNginx(line)호출
func ParseRecentLogs(n int) []AccessEntry {
	f, err := os.Open(nginxLogPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	//nginx로그를 읽어와 lines에 저장
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	//로그는 첫번째 줄이 오래된 로그이므로 순서를 뒤집어서 저장
	raw := make([]AccessEntry, 0, len(lines))
	for _, line := range lines {
		//각 줄의 파싱은 parseNginxLine
		if e, ok := parseNginxLine(line); ok {
			raw = append(raw, e)
		}
	}
	//순서 뒤집는 코드
	for i, j := 0, len(raw)-1; i < j; i, j = i+1, j-1 {
		raw[i], raw[j] = raw[j], raw[i]
	}
	//내 pc ip 하드코딩
	entries := make([]AccessEntry, 0, len(raw))
	for _, e := range raw {
		if e.IP == "203.247.166.251" {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}
//각 줄 파싱
func parseNginxLine(line string) (AccessEntry, bool) {
	//ip추출
	parts := strings.SplitN(line, " ", 2)
	//pars가 2이하 : 메서드 없는 쉘코드이므로 false return
	if len(parts) < 2 {
		return AccessEntry{}, false
	}
	ip := parts[0]

	//시간 추출 "[07/May/2026:10:00:00 +0000]" → "07/May/2026:10:00:00 +0000"
	timeStart := strings.Index(line, "[")
	timeEnd := strings.Index(line, "]")
	//시간이 비정상적
	if timeStart < 0 || timeEnd < 0 {
		return AccessEntry{}, false
	}
	rawTime := line[timeStart+1 : timeEnd]

	reqStart := strings.Index(line[timeEnd:], `"`)
	reqEnd := strings.Index(line[timeEnd+reqStart+1:], `"`)
	//요청 시작과 요청 끝이 비정상적
	if reqStart < 0 || reqEnd < 0 {
		return AccessEntry{}, false
	}
	//실제 값 추출 -> GET /index HTTP/1.1
	req := line[timeEnd+reqStart+1 : timeEnd+reqStart+1+reqEnd]
	//req문자를 공백 기준으로 쪼개서 슬라이스로 만듬
	reqParts := strings.Fields(req)
	method, path := "", ""
	//reqParts의 0번째와 1번째 인덱스
	if len(reqParts) >= 2 {
		method = reqParts[0]
		path = reqParts[1]
	}

	if !validMethods[method] {
		return AccessEntry{}, false
	}
	// AccessEntry를 만들어서 반환
	return AccessEntry{
		Time:   rawTime,
		IP:     ip,
		Method: method,
		Path:   path,
	}, true
}
