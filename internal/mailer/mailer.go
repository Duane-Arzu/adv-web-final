package mailer

import (
	"bytes"
	"embed"
	"html/template"
	"time"

	"github.com/go-mail/mail/v2"
)

// Embed static template files directly into the application
//
//go:embed "templates"
var templateFS embed.FS // Holds embedded template files

// Mailer manages SMTP settings and sender details
type Mailer struct {
	dialer *mail.Dialer // SMTP connection
	sender string       // Email sender address
}

// Initialize a new Mailer instance with SMTP configuration
func New(host string, port int, username, password, sender string) Mailer {
	dialer := mail.NewDialer(host, port, username, password)
	dialer.Timeout = 5 * time.Second

	return Mailer{
		dialer: dialer,
		sender: sender,
	}
}

// Send an email using the specified template and dynamic data
func (m Mailer) Send(recipient, templateFile string, data any) error {
	// Parse the template file from embedded templates
	tmpl, err := template.New("email").ParseFS(templateFS, "templates/"+templateFile)
	if err != nil {
		return err
	}

	// Generate the email subject from the template
	subject := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}

	// Generate the plain-text body
	plainBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(plainBody, "plainBody", data)
	if err != nil {
		return err
	}

	// Generate the HTML body
	htmlBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(htmlBody, "htmlBody", data)
	if err != nil {
		return err
	}

	// Compose the email message
	msg := mail.NewMessage()
	msg.SetHeader("To", recipient)
	msg.SetHeader("From", m.sender)
	msg.SetHeader("Subject", subject.String())
	msg.SetBody("text/plain", plainBody.String())
	msg.AddAlternative("text/html", htmlBody.String())

	// Attempt to send the email with retries
	for i := 1; i <= 3; i++ {
		err = m.dialer.DialAndSend(msg)
		if err == nil { // Success
			return nil
		}
		time.Sleep(500 * time.Millisecond) // Short delay before retrying
	}

	// Return the error if all attempts fail
	return err
}
