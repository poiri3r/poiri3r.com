package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func Init() {
	var err error
	DB, err = sql.Open("sqlite3", "./data.db")
	if err != nil {
		panic(err)
	}

	DB.Exec(`CREATE TABLE IF NOT EXISTS portfolio (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT,
		description TEXT,
		url TEXT
	)`)

	DB.Exec(`CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		message TEXT,
		level TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
}
