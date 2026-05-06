package models

type Portfolio struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

type Log struct {
	ID        int    `json:"id"`
	Message   string `json:"message"`
	Level     string `json:"level"`
	CreatedAt string `json:"created_at"`
}
