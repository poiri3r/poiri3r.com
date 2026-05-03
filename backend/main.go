package main

import (
	"net/http"
	"example.com/db"
	"example.com/handlers"
)

func main() {
	db.Init()

	mux := http.NewServeMux()

	// 정적 파일 서빙
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("../frontend"))))

	// 페이지 라우터
	mux.HandleFunc("/", handlers.IndexPage)
	mux.HandleFunc("/portfolio", handlers.PortfolioPage)
	mux.HandleFunc("/stack", handlers.StackPage)
	mux.HandleFunc("/logs", handlers.LogsPage)

	// API 라우터
	mux.HandleFunc("/api/portfolio", handlers.GetPortfolio)
	mux.HandleFunc("/api/logs", handlers.GetLogs)
	mux.HandleFunc("/api/blog", handlers.GetBlog)

	http.ListenAndServe(":3000", mux)
}
