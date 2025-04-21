package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	ctx  context.Context
	conn *pgxpool.Pool
}

func New(url string) (*Postgres, error) {
	db, err := pgxpool.New(context.Background(), url)

	return &Postgres{
		ctx:  context.Background(),
		conn: db,
	}, err
}

func (p *Postgres) NewRefreshToken(rToken []byte) (int, error) {
	var id int
	err := p.conn.QueryRow(p.ctx, "INSERT INTO refresh_tokens (refresh_token) VALUES ($1) RETURNING id", rToken).Scan(&id)

	return id, err
}

func (p *Postgres) GetRefreshTokenID(refreshTokenID int) (string, error) {
	var rToken string
	err := p.conn.QueryRow(p.ctx, "SELECT refresh_token FROM refresh_tokens WHERE id = $1", refreshTokenID).Scan(&rToken)

	return rToken, err
}

func (p *Postgres) DeleteRefreshToken(ID int) error {
	_, err := p.conn.Exec(p.ctx, "DELETE FROM refresh_tokens WHERE id = $1", ID)

	return err
}
