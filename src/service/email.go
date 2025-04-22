package service

import (
	"awesomeProject1/errHandler"
	"log"
)

// Пустая функция, которая имитирует отправку email
func SendEmail(to, oldIP, newIP string) error {
	log.Printf("Адрес пользователя %s сменился с %s на %s", to, oldIP, newIP)

	return errHandler.New(errHandler.ErrEmail, nil)
}
