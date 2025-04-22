package main

import (
	"awesomeProject1/handler"
	"awesomeProject1/infrastructure"
	"awesomeProject1/repository/postgres"
	"awesomeProject1/service/auth"
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

	pgx, err := infrastructure.NewPostgres(postgresURL)

	db := &postgres.Repository{Postgres: pgx}

	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	Service := auth.NewService(tokenKey, rTokenKey, db)
	handler.ListenAndServe(Service)
}
