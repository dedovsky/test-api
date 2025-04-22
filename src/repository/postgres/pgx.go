package postgres

import (
	"awesomeProject1/infrastructure"
	"context"
)

type Repository struct {
	*infrastructure.Postgres
}

func (p *Repository) NewRefreshToken(rToken []byte, ctx context.Context) (int, error) {
	var id int
	err := p.Conn.QueryRow(ctx, "INSERT INTO refresh_tokens (refresh_token) VALUES ($1) RETURNING id", rToken).Scan(&id)

	return id, err
}

func (p *Repository) GetRefreshTokenID(refreshTokenID int, ctx context.Context) (string, error) {
	var rToken string
	err := p.Conn.QueryRow(ctx, "SELECT refresh_token FROM refresh_tokens WHERE id = $1", refreshTokenID).Scan(&rToken)

	return rToken, err
}

func (p *Repository) DeleteRefreshToken(ID int, ctx context.Context) error {
	_, err := p.Conn.Exec(ctx, "DELETE FROM refresh_tokens WHERE id = $1", ID)

	return err
}
