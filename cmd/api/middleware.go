package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"net"
	"time"

	"github.com/Duane-Arzu/adv-web-final.git/internal/data"
	"github.com/Duane-Arzu/adv-web-final.git/internal/validator"

	"golang.org/x/time/rate"
)

func (a *applicationDependencies) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Recover from any panics and return a server error
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Connection", "close")
				a.serverErrorResponse(w, r, fmt.Errorf("%s", err))
			}
		}()
		// Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func (a *applicationDependencies) rateLimit(next http.Handler) http.Handler {
	// Client struct stores rate limiter and last activity timestamp
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var mu sync.Mutex
	var clients = make(map[string]*client)

	// Periodic cleanup for inactive clients
	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			for ip, client := range clients {
				if time.Since(client.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.config.limiter.enabled {
			// Extract client IP address
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				a.serverErrorResponse(w, r, err)
				return
			}

			mu.Lock()

			// Initialize limiter for new clients
			if _, found := clients[ip]; !found {
				clients[ip] = &client{
					limiter: rate.NewLimiter(rate.Limit(a.config.limiter.rps), a.config.limiter.burst),
				}
			}
			clients[ip].lastSeen = time.Now()

			// Deny request if rate limit exceeded
			if !clients[ip].limiter.Allow() {
				mu.Unlock()
				a.rateLimitExceededResponse(w, r)
				return
			}
			mu.Unlock()
		}
		// Pass request to the next handler
		next.ServeHTTP(w, r)
	})
}

func (a *applicationDependencies) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for the Authorization header
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			r = a.contextSetUser(r, data.AnonymousUser) // Assign anonymous user
			next.ServeHTTP(w, r)
			return
		}

		// Validate the Bearer token format
		headerParts := strings.Split(authorizationHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			a.invalidAuthenticationTokenResponse(w, r)
			return
		}

		token := headerParts[1]
		v := validator.New()
		data.ValidateTokenPlaintext(v, token)
		if !v.IsEmpty() {
			a.invalidAuthenticationTokenResponse(w, r)
			return
		}

		// Fetch user associated with the token
		user, err := a.userModel.GetForToken(data.ScopeAuthentication, token)
		if err != nil {
			switch {
			case errors.Is(err, data.ErrRecordNotFound):
				a.invalidAuthenticationTokenResponse(w, r)
			default:
				a.serverErrorResponse(w, r, err)
			}
			return
		}
		// Set the user in the request context
		r = a.contextSetUser(r, user)

		// Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func (a *applicationDependencies) requireAuthenticatedUser(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure the user is authenticated
		user := a.contextGetUser(r)
		if user.IsAnonymous() {
			a.authenticationRequiredResponse(w, r) // Return 401 Unauthorized
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *applicationDependencies) requireActivatedUser(next http.HandlerFunc) http.HandlerFunc {
	// Middleware to ensure the user is activated
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := a.contextGetUser(r)
		if !user.Activated {
			a.inactiveAccountResponse(w, r) // Return 403 Forbidden
			return
		}
		next.ServeHTTP(w, r)
	})

	// Chain with requireAuthenticatedUser to ensure both authentication and activation
	return a.requireAuthenticatedUser(fn)
}

func (a *applicationDependencies) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")

		// Let's check the request origin to see if it's in the trusted list
		origin := r.Header.Get("Origin")
		// Once we have a origin from the request header we need need to check
		if origin != "" {
			for i := range a.config.cors.trustedOrigins {
				if origin == a.config.cors.trustedOrigins[i] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					if r.Method == http.MethodOptions &&
					r.Header.Get("Access-Control-Request-Method") != "" {
					w.Header().Set("Access-Control-Allow-Methods",
						"OPTIONS, PUT, PATCH, DELETE")
					w.Header().Set("Access-Control-Allow-Headers",
						"Authorization, Content-Type")
					w.WriteHeader(http.StatusOK)
					return
				}

				break
			}
		}
	}
	next.ServeHTTP(w,r)
})
}
