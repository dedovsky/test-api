package service

import "log"

func SendEmail(to, oldIP, newIP string) error {
	log.Printf("Адрес пользователя %s сменился с %s на %s", to, oldIP, newIP)

	return nil
}
