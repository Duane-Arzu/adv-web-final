package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/data"
	"github.com/Duane-Arzu/test3.git/internal/mailer"
	_ "github.com/lib/pq"
)

const appVersion = "7.0.0"

type serverConfig struct {
	port        int
	environment string
	db          struct {
		dsn string
	}
	limiter struct {
		rps     float64 // requests per second
		burst   int     // initial requests possible
		enabled bool    // enable or disable rate limiter
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		sender   string
	}
}

type applicationDependencies struct {
	config           serverConfig
	logger           *slog.Logger
	bookModel        data.BookModel
	readingListModel data.ReadingListModel
	reviewModel      data.ReviewModel
	userModel        data.UserModel
	mailer           mailer.Mailer
	wg               sync.WaitGroup
	tokenModel       data.TokenModel
}

func main() {
	var setting serverConfig

	flag.IntVar(&setting.port, "port", 4000, "Server port")
	flag.StringVar(&setting.environment, "env", "development", "Environment (development|staging|production)")
	flag.StringVar(&setting.db.dsn, "db-dsn", "postgres://test3:test3@localhost/test3?sslmode=disable", "PostgreSQL DSN")

	flag.Float64Var(&setting.limiter.rps, "limiter-rps", 2, "Rate Limiter maximum requests per second")

	flag.IntVar(&setting.limiter.burst, "limiter-burst", 5, "Rate Limiter maximum burst")

	flag.BoolVar(&setting.limiter.enabled, "limiter-enabled", true, "Enable rate limiter")

	flag.StringVar(&setting.smtp.host, "smtp-host", "sandbox.smtp.mailtrap.io", "SMTP host")
	// We have port 25, 465, 587, 2525. If 25 doesn't work choose another
	flag.IntVar(&setting.smtp.port, "smtp-port", 2525, "SMTP port")
	// Use your Username value provided by Mailtrap
	flag.StringVar(&setting.smtp.username, "smtp-username", "147f39f67b641b", "SMTP username")

	flag.StringVar(&setting.smtp.password, "smtp-password", "00deefca7111e6", "SMTP password")

	flag.StringVar(&setting.smtp.sender, "smtp-sender", "Book Club Management Community <no-reply@commentscommunity.duanearzu.net>", "SMTP sender")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// the call to openDB() sets up our connection pool
	db, err := openDB(setting)
	if err != nil {
		logger.Error("Database connection failed")
		os.Exit(1)
	}
	// release the database resources before exiting
	defer db.Close()

	logger.Info("Database connection pool established")

	appInstance := &applicationDependencies{
		config:           setting,
		logger:           logger,
		userModel:        data.UserModel{DB: db},
		bookModel:        data.BookModel{DB: db},
		readingListModel: data.ReadingListModel{DB: db},
		reviewModel:      data.ReviewModel{DB: db},
		tokenModel:       data.TokenModel{DB: db},
		mailer: mailer.New(setting.smtp.host, setting.smtp.port,
			setting.smtp.username, setting.smtp.password, setting.smtp.sender),
	}

	err = appInstance.serve()
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func openDB(settings serverConfig) (*sql.DB, error) {
	// open a connection pool
	db, err := sql.Open("postgres", settings.db.dsn)
	if err != nil {
		return nil, err
	}

	// set a context to ensure DB operations don't take too long
	ctx, cancel := context.WithTimeout(context.Background(),
		5*time.Second)
	defer cancel()

	// let's test if the connection pool was created
	// we trying pinging it with a 5-second timeout
	err = db.PingContext(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}

	// return the connection pool (sql.DB)
	return db, nil

}
