package auth

import (
	"perimeter/ent"
	"perimeter/ent/user"

	"github.com/gofiber/fiber/v2"
)

const (
	// UserKey is the Fiber locals key for the authenticated user.
	UserKey = "user"
	// SessionCookie is the name of the session cookie.
	SessionCookie = "perimeter_session"
)

// RequireAuth returns middleware that checks for a valid session cookie
// and loads the user into c.Locals(UserKey).
func RequireAuth(a *Auth) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies(SessionCookie)
		if token == "" {
			return c.Redirect("/login")
		}

		u, err := a.ValidateSession(c.Context(), token)
		if err != nil {
			// Invalid or expired session
			return c.Redirect("/login")
		}

		c.Locals(UserKey, u)
		return c.Next()
	}
}

// RequireRole returns middleware that checks the authenticated user has
// the required role. Must be used after RequireAuth.
func RequireRole(role user.Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u, ok := c.Locals(UserKey).(*ent.User)
		if !ok || u == nil {
			return c.Redirect("/login")
		}

		if u.Role != role {
			return c.Status(fiber.StatusForbidden).SendString("Forbidden")
		}

		return c.Next()
	}
}

// GetUser retrieves the authenticated user from Fiber locals.
func GetUser(c *fiber.Ctx) *ent.User {
	u, _ := c.Locals(UserKey).(*ent.User)
	return u
}
