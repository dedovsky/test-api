package main

import (
	"awesomeProject1/internal/handler"
	"awesomeProject1/internal/repository/postgres"
	"awesomeProject1/internal/service/auth"
	"log"
	"os"
)

func main() {
	tokenKey := os.Getenv("TOKEN_KEY")
	rTokenKey := os.Getenv("REFRESH_TOKEN_KEY")
	postgresURL := os.Getenv("POSTGRES_URL")

	switch {
	case tokenKey == "":
		log.Fatal("TOKEN_KEY is not set")
	case rTokenKey == "":
		log.Fatal("REFRESH_TOKEN_KEY is not set")
	case postgresURL == "":
		log.Fatal("POSTGRES_URL is not set")
	}

	db, err := postgres.New(postgresURL)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	Service := auth.NewService(tokenKey, rTokenKey, db)
	handler.ListenAndServe(Service)
}
