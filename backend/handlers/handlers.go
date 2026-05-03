package handlers

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
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
	Title    string `xml:"title"`
	Link     string `xml:"link"`
	PubDate  string `xml:"pubDate"`
	Category string `xml:"category"`
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

	type BlogPost struct {
		Title   string `json:"title"`
		Link    string `json:"link"`
		PubDate string `json:"pub_date"`
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
	json.NewEncoder(w).Encode(posts)
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
