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
	// Configure the HTTP server with settings like port, timeouts, and error logging
	apiServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", a.config.port),                      // Set server port
		Handler:      a.routes(),                                             // Use the defined routes
		IdleTimeout:  time.Minute,                                            // Max idle time for a connection
		ReadTimeout:  5 * time.Second,                                        // Max time to read a request
		WriteTimeout: 10 * time.Second,                                       // Max time to write a response
		ErrorLog:     slog.NewLogLogger(a.logger.Handler(), slog.LevelError), // Log errors
	}

	// Log that the server is starting
	a.logger.Info("starting server", "address", apiServer.Addr,
		"environment", a.config.environment)

	// Channel to track shutdown errors
	shutdownError := make(chan error)

	// Run a separate task to handle shutdown gracefully
	go func() {
		quit := make(chan os.Signal, 1)                      // Channel to capture OS signals
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM) // Listen for termination signals
		s := <-quit                                          // Wait for a signal to be received

		// Log the shutdown signal
		a.logger.Info("shutting down server", "signal", s.String())

		// Create a timeout context for the shutdown process
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Shut down the server gracefully
		err := apiServer.Shutdown(ctx)
		if err != nil {
			shutdownError <- err // Send error to channel if shutdown fails
		}

		// Wait for all background tasks to finish
		a.logger.Info("completing background tasks", "address", apiServer.Addr)
		a.wg.Wait()

		// Notify the channel that shutdown is done
		shutdownError <- nil
	}()

	// Start the server and handle any errors
	err := apiServer.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err // Return if the error is not a "server closed" error
	}

	// Wait for the shutdown process to finish
	err = <-shutdownError
	if err != nil {
		return err // Return error if shutdown failed
	}

	// Log that the server has stopped
	a.logger.Info("stopped server", "address", apiServer.Addr)

	return nil
}
