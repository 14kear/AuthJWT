package email

import (
	"fmt"
	"time"

	"github.com/go-mail/mail/v2"
)

type SMTPClient struct {
	dialer *mail.Dialer
	from   string
}

func NewSMTPClient(host string, port int, username, password, from string) *SMTPClient {
	dialer := mail.NewDialer(host, port, username, password)
	dialer.Timeout = 30 * time.Second

	// УПРОЩЕННАЯ НАСТРОЙКА ДЛЯ SENDGRID И ДРУГИХ PRODUCTION SMTP
	if port == 587 {
		// SendGrid использует STARTTLS на порту 587
		dialer.StartTLSPolicy = mail.MandatoryStartTLS
	} else if port == 465 {
		// SMTPS (устаревший)
		dialer.SSL = true
		dialer.StartTLSPolicy = mail.NoStartTLS
	} else {
		// Для остальных случаев - автоопределение
		dialer.StartTLSPolicy = mail.OpportunisticStartTLS
	}

	return &SMTPClient{
		dialer: dialer,
		from:   from,
	}
}

func (s *SMTPClient) SendVerificationCode(to, code string) error {
	fmt.Printf("=== SMTP CLIENT CALLED ===\n")
	fmt.Printf("Connecting to: %s:%d\n", s.dialer.Host, s.dialer.Port)
	fmt.Printf("Sending to: %s\n", to)
	fmt.Printf("Code: %s\n", code)

	msg := mail.NewMessage()
	msg.SetHeader("From", s.from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", "Код подтверждения")
	msg.SetHeader("X-Priority", "1") // Высокий приоритет для кодов подтверждения

	// Plain text версия
	msg.SetBody("text/plain", fmt.Sprintf(
		"Ваш код подтверждения: %s\nДействителен 10 минут.\n\nЕсли вы не запрашивали этот код — проигнорируйте письмо.",
		code,
	))

	// HTML версия для лучшей доставляемости
	msg.AddAlternative("text/html", fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="utf-8">
			<style>
				body { font-family: Arial, sans-serif; color: #333; line-height: 1.6; }
				.code { font-size: 32px; font-weight: bold; color: #2563eb; text-align: center; margin: 20px 0; padding: 15px; background: #f3f4f6; border-radius: 8px; }
				.container { max-width: 600px; margin: 0 auto; padding: 20px; }
				.footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; }
				.header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
				.content { background: #ffffff; padding: 20px; border-radius: 0 0 8px 8px; border: 1px solid #e5e7eb; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h1>Подтверждение регистрации</h1>
				</div>
				<div class="content">
					<p>Здравствуйте!</p>
					<p>Для завершения регистрации используйте следующий код подтверждения:</p>
					<div class="code">%s</div>
					<p><strong>Код действителен 10 минут.</strong></p>
					<p>Если вы не запрашивали регистрацию, пожалуйста, проигнорируйте это письмо.</p>
				</div>
				<div class="footer">
					<p>С уважением,<br>Команда приложения</p>
				</div>
			</div>
		</body>
		</html>
	`, code))

	fmt.Printf("=== ATTEMPTING TO SEND ===\n")

	// Пробуем отправить с переподключением
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Printf("Attempt %d...\n", attempt)

		err = s.dialer.DialAndSend(msg)
		if err == nil {
			fmt.Printf("=== EMAIL SENT SUCCESSFULLY ===\n")
			return nil
		}

		fmt.Printf("=== SMTP ATTEMPT %d ERROR: %v ===\n", attempt, err)

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	fmt.Printf("=== FINAL SMTP ERROR: %v ===\n", err)
	return fmt.Errorf("failed to send email after 3 attempts: %w", err)
}
