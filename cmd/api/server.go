// Filename: cmd/api/server.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (a *applicationDependencies) serve() error {
	apiServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", a.config.port),
		Handler:      a.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     slog.NewLogLogger(a.logger.Handler(), slog.LevelError),
	}

	a.logger.Info("starting server", "address", apiServer.Addr,
		"environment", a.config.environment)

	// Create a channel to track errors during shutdown
	shutdownError := make(chan error)

	// Run a goroutine to handle graceful shutdown
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		s := <-quit // Block until a signal is received

		a.logger.Info("shutting down server", "signal", s.String())

		// Create a context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := apiServer.Shutdown(ctx)
		if err != nil {
			shutdownError <- err
		}
		// Wait for background tasks to complete
		a.logger.Info("completing background tasks", "address", apiServer.Addr)
		a.wg.Wait()
		shutdownError <- nil

	}()

	// Start the server
	err := apiServer.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	// Wait for shutdown to complete
	err = <-shutdownError
	if err != nil {
		return err
	}

	a.logger.Info("stopped server", "address", apiServer.Addr)

	return nil
}
