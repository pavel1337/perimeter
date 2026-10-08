package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestCrossOriginProtection(t *testing.T) {
	app := fiber.New()
	app.Use(crossOriginProtection())
	app.All("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"get cross-site", "GET", map[string]string{"Sec-Fetch-Site": "cross-site"}, 200},
		{"post same-origin", "POST", map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
		{"post user-initiated", "POST", map[string]string{"Sec-Fetch-Site": "none"}, 200},
		{"post cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"post same-site", "POST", map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"post matching origin", "POST", map[string]string{"Origin": "http://example.com"}, 200},
		{"post foreign origin", "POST", map[string]string{"Origin": "https://evil.example"}, 403},
		{"post no headers", "POST", nil, 200},
	}
	// Same-origin with a port, as in local runs: the Host comparison must
	// include it.
	t.Run("post matching origin with port", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://localhost:8080/", nil)
		req.Header.Set("Origin", "http://localhost:8080")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://example.com/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}
