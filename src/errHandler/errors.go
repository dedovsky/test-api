package errHandler

import (
	"fmt"
	"log"
)

type ErrorType string

const (
	ErrInvalidToken ErrorType = "invalid_token"
	ErrInternal     ErrorType = "internal_error"
	ErrEmail        ErrorType = "email_error"
)

var errorDefs = map[ErrorType]struct {
	Code int
	Msg  string
}{
	ErrInvalidToken: {400, "Токен не валиден"},
	ErrInternal:     {500, "Произошла внутренняя ошибка"},
}

type CustomError struct {
	Type    ErrorType
	Code    int
	Message string
	Err     error
}

func (e *CustomError) Error() string {
	return fmt.Sprintf("type: %s, code: %d, msg: %s, err: %v", e.Type, e.Code, e.Message, e.Err)
}

func New(t ErrorType, err error) *CustomError {
	def, exists := errorDefs[t]
	if !exists {
		def = errorDefs[ErrInternal]
	}

	if err != nil {
		log.Printf("Ошибка %s (type: %s, code: %d): %v", def.Msg, t, def.Code, err)
	}

	return &CustomError{Type: t, Code: def.Code, Message: def.Msg, Err: err}
}
