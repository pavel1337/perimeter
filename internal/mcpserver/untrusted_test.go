package mcpserver

import (
	"testing"
	"time"

	"perimeter/ent/apitoken"
	"perimeter/ent/user"
	"perimeter/internal/storage"
)

// T and M grades get their own category with the reason, and stay out of
// weak_ssl, so a real F isn't buried (issue #73).
func TestFindIssuesUntrustedCerts(t *testing.T) {
	f := newFixture(t)
	_, err := f.st.ImportTargets(f.ctx, []string{"proxy.test", "weak.test"})
	f.must(err)
	exp := time.Now().Add(300 * 24 * time.Hour)
	f.must(f.st.SaveSSLScan(f.ctx, "proxy.test", storage.SSLResult{Grade: "T", Status: "READY", CertExpiry: exp, CertIssues: storage.CertSelfSigned}))
	f.must(f.st.SaveSSLScan(f.ctx, "weak.test", storage.SSLResult{Grade: "F", Status: "READY", CertExpiry: exp}))
	raw, _ := f.token("viewer@test.com", user.RoleViewer, apitoken.ScopeRead)
	cs := f.connect(raw)

	res := call(t, cs, "find_issues", map[string]any{"categories": []string{"weak_ssl", "untrusted_certs"}})
	var out IssuesOut
	decode(t, res, &out)
	if len(out.Groups) != 2 {
		t.Fatalf("groups = %+v", out.Groups)
	}
	weak, untrusted := out.Groups[0], out.Groups[1]
	if weak.Total != 1 || weak.Targets[0].Input != "weak.test" {
		t.Errorf("weak_ssl = %+v, want only the F", weak)
	}
	if untrusted.Total != 1 || untrusted.Targets[0].Reason != "SSL grade T: self-signed" {
		t.Errorf("untrusted_certs = %+v, want proxy.test with its reason", untrusted)
	}
}
