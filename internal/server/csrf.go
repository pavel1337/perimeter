package server

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// crossOriginProtection rejects state-changing requests that a browser sent
// from another origin, the CSRF defence for every POST form (issue #18). It
// reuses net/http's CrossOriginProtection: requests whose Sec-Fetch-Site or
// Origin header shows a cross-site origin are refused, while same-origin
// requests and non-browser clients (no such headers) pass. Safe methods are
// never checked. No tokens, so forms need no hidden field.
//
// The Origin fallback compares against the Host header, so a reverse proxy in
// front of perimeter must preserve Host.
func crossOriginProtection() fiber.Handler {
	cop := http.NewCrossOriginProtection()
	return func(c *fiber.Ctx) error {
		req := &http.Request{
			Method: c.Method(),
			Host:   string(c.Request().Host()),
			Header: http.Header{},
		}
		for _, h := range []string{"Sec-Fetch-Site", "Origin"} {
			if v := c.Get(h); v != "" {
				req.Header.Set(h, v)
			}
		}
		if err := cop.Check(req); err != nil {
			return c.Status(fiber.StatusForbidden).SendString("Cross-origin request blocked")
		}
		return c.Next()
	}
}
