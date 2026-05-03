package handlers

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"regexp"
	"strconv"
	"io"
	"example.com/db"
	"example.com/models"
)

// RSS 구조체
type RSSFeed struct {
	Channel RSSChannel `xml:"channel"`
}

type RSSChannel struct {
	Items []RSSItem `xml:"item"`
}

type RSSItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	PubDate string `xml:"pubDate"`
}

// 페이지 핸들러
func IndexPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/index.html")
}

func PortfolioPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/portfolio.html")
}

func StackPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/stack.html")
}

func LogsPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/logs.html")
}

// Blog RSS 핸들러
func GetBlog(w http.ResponseWriter, r *http.Request) {
	// RSS 파싱
	rssResp, err := http.Get("https://poiri3r.tistory.com/rss")
	if err != nil {
		http.Error(w, "RSS 요청 실패", http.StatusInternalServerError)
		return
	}
	defer rssResp.Body.Close()

	var feed RSSFeed
	if err := xml.NewDecoder(rssResp.Body).Decode(&feed); err != nil {
		http.Error(w, "RSS 파싱 실패", http.StatusInternalServerError)
		return
	}

	// 전체 글 수 파싱 (블로그 메인 HTML에서)
	total := 0
	htmlResp, err := http.Get("https://poiri3r.tistory.com")
	if err == nil {
		defer htmlResp.Body.Close()
		body, err := io.ReadAll(htmlResp.Body)
		if err == nil {
			// 티스토리 HTML에서 전체 글 수 추출
			re := regexp.MustCompile(`total_count[^>]*>([0-9,]+)<`)
			matches := re.FindSubmatch(body)
			if len(matches) > 1 {
				countStr := regexp.MustCompile(`[^0-9]`).ReplaceAllString(string(matches[1]), "")
				total, _ = strconv.Atoi(countStr)
			}
		}
	}

	type BlogPost struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		PubDate string `json:"pub_date"`
	}

	type BlogResponse struct {
		Total int        `json:"total"`
		Posts []BlogPost `json:"posts"`
	}

	var posts []BlogPost
	for _, item := range feed.Channel.Items {
		posts = append(posts, BlogPost{
			Title:   item.Title,
			Link:    item.Link,
			PubDate: item.PubDate,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(BlogResponse{
		Total: total,
		Posts: posts,
	})
}

// API 핸들러
func GetPortfolio(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query("SELECT id, title, description, url FROM portfolio")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var portfolios []models.Portfolio
	for rows.Next() {
		var p models.Portfolio
		rows.Scan(&p.ID, &p.Title, &p.Description, &p.URL)
		portfolios = append(portfolios, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(portfolios)
}

func GetLogs(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query("SELECT id, message, level, created_at FROM logs ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []models.Log
	for rows.Next() {
		var l models.Log
		rows.Scan(&l.ID, &l.Message, &l.Level, &l.CreatedAt)
		logs = append(logs, l)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}
