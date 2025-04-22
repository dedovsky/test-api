package infrastructure

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	Conn *pgxpool.Pool
}

func NewPostgres(url string) (*Postgres, error) {
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}

	return &Postgres{
		Conn: db,
	}, nil
}
