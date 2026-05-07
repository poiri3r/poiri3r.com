package main

import (
	"net/http"
	"example.com/collector"
	"example.com/db"
	"example.com/handlers"
)

func main() {
	db.Init() //데베
	go collector.Start() //로그 수집

	//multiplexer
	mux := http.NewServeMux()


	// frontend서버를 파일 서버로 만듬
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("../frontend"))))

	// 페이지 라우터
	mux.HandleFunc("/", handlers.IndexPage)
	//mux.HandleFunc("/portfolio", handlers.PortfolioPage)
	mux.HandleFunc("/stack", handlers.StackPage)
	mux.HandleFunc("/logs", handlers.LogsPage)

	// API 라우터
	mux.HandleFunc("/api/visitors/summary", handlers.GetVisitorSummary)
	mux.HandleFunc("/api/visitors/refresh", handlers.RefreshVisitorSummary)
	mux.HandleFunc("/api/visitors/detail", handlers.GetVisitorDetail)
	mux.HandleFunc("/api/dashboard", handlers.GetDashboard)
	mux.HandleFunc("/api/crowdsec/alerts", handlers.GetCrowdsecAlerts)
	//mux.HandleFunc("/api/portfolio", handlers.GetPortfolio)
	mux.HandleFunc("/api/blog", handlers.GetBlog)

	//3000번 포트 사용 (nginx에서 리버스프록시)
	http.ListenAndServe(":3000", mux)
}
