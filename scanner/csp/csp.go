package csp

import (
	"net/url"
	"regexp"
	"strings"
)

// Evaluator defines the interface for evaluating a Content Security Policy.
type Evaluator interface {
	Evaluate(csp string) ([]Finding, error)
}

// CheckFunc is a function that checks a parsed CSP and returns findings.
type CheckFunc func(csp *Csp) []Finding

// DefaultEvaluator implements the Evaluator interface.
type DefaultEvaluator struct {
	checks []CheckFunc
}

// NewEvaluator creates a new DefaultEvaluator with standard checks.
func NewEvaluator() Evaluator {
	return &DefaultEvaluator{
		checks: []CheckFunc{
			CheckScriptUnsafeInline,
			CheckScriptUnsafeEval,
			CheckPlainUrlSchemes,
			CheckWildcards,
			CheckMissingDirectives,
			CheckScriptAllowlistBypass,
			CheckFlashObjectAllowlistBypass,
			CheckIpSource,
			CheckNonceLength,
		},
	}
}

// Evaluate parses the CSP string and applies all configured checks.
func (e *DefaultEvaluator) Evaluate(cspInput string) ([]Finding, error) {
	parsed := Parse(cspInput)
	var allFindings []Finding
	for _, check := range e.checks {
		findings := check(parsed)
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

// Keyword constants
const (
	KeywordSelf          = "'self'"
	KeywordNone          = "'none'"
	KeywordUnsafeInline  = "'unsafe-inline'"
	KeywordUnsafeEval    = "'unsafe-eval'"
	KeywordStrictDynamic = "'strict-dynamic'"
	KeywordUnsafeHashes  = "'unsafe-hashes'"
	KeywordReportSample  = "'report-sample'"
	KeywordBlock         = "'block'"
	KeywordAllow         = "'allow'"
)

// Directive constants
const (
	DirectiveDefaultSrc    = "default-src"
	DirectiveScriptSrc     = "script-src"
	DirectiveScriptSrcAttr = "script-src-attr"
	DirectiveScriptSrcElem = "script-src-elem"
	DirectiveObjectSrc     = "object-src"
	DirectiveStyleSrc      = "style-src"
	DirectiveImgSrc        = "img-src"
	DirectiveConnectSrc    = "connect-src"
	DirectiveFontSrc       = "font-src"
	DirectiveFrameSrc      = "frame-src"
	DirectiveMediaSrc      = "media-src"
	DirectiveManifestSrc   = "manifest-src"
	DirectiveWorkerSrc     = "worker-src"
	DirectiveBaseUri       = "base-uri"
	DirectiveReportUri     = "report-uri"
	DirectiveReportTo      = "report-to"
	DirectivePluginTypes   = "plugin-types"
)

var DirectivesCausingXss = []string{
	DirectiveScriptSrc, DirectiveScriptSrcAttr, DirectiveScriptSrcElem,
	DirectiveObjectSrc, DirectiveBaseUri,
}

var UrlSchemesCausingXss = []string{"data:", "http:", "https:"}

// Csp represents a parsed Content Security Policy.
type Csp struct {
	Directives map[string][]string
}

// NewCsp creates a new empty CSP.
func NewCsp() *Csp {
	return &Csp{
		Directives: make(map[string][]string),
	}
}

// Parse parses a CSP string into a Csp struct.
func Parse(unparsedCsp string) *Csp {
	csp := NewCsp()
	tokens := strings.Split(unparsedCsp, ";")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		parts := strings.Fields(token)
		if len(parts) == 0 {
			continue
		}
		directiveName := strings.ToLower(parts[0])

		// If already present, ignore (first one wins)
		if _, ok := csp.Directives[directiveName]; ok {
			continue
		}

		var values []string
		seen := make(map[string]bool)
		for _, val := range parts[1:] {
			// Normalize
			// Remove whitespaces (already done by field split)
			valLower := strings.ToLower(val)
			normalized := val
			if isKeyword(valLower) || isUrlScheme(val) {
				normalized = valLower
			}

			if !seen[normalized] {
				values = append(values, normalized)
				seen[normalized] = true
			}
		}
		csp.Directives[directiveName] = values
	}
	return csp
}

func isKeyword(val string) bool {
	// Simple check generally used in TS code
	return strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")
}

func isUrlScheme(val string) bool {
	return strings.HasSuffix(val, ":")
}

// GetEffectiveDirectives returns the effective directives for a list of directives.
func (c *Csp) GetEffectiveDirectives(directives []string) []string {
	effective := make(map[string]bool)
	for _, d := range directives {
		effective[c.GetEffectiveDirective(d)] = true
	}
	var result []string
	for k := range effective {
		result = append(result, k)
	}
	return result
}

// GetEffectiveDirective returns the effective directive (fallback to default-src).
func (c *Csp) GetEffectiveDirective(directive string) string {
	if _, ok := c.Directives[directive]; ok {
		return directive
	}
	if directive == DirectiveScriptSrcAttr || directive == DirectiveScriptSrcElem {
		if _, ok := c.Directives[DirectiveScriptSrc]; ok {
			return DirectiveScriptSrc
		}
	}
	// Fallback to default-src for fetch directives
	// Simplified list for now
	fetchDirectives := map[string]bool{
		DirectiveScriptSrc: true, DirectiveObjectSrc: true, DirectiveStyleSrc: true,
		DirectiveImgSrc: true, DirectiveConnectSrc: true, DirectiveFontSrc: true,
		DirectiveFrameSrc: true, DirectiveMediaSrc: true, DirectiveWorkerSrc: true,
		DirectiveManifestSrc: true, DirectiveChildSrc: true,
	}
	// DirectiveChildSrc constant needed

	if fetchDirectives[directive] {
		return DirectiveDefaultSrc
	}
	return directive
}

const DirectiveChildSrc = "child-src"

// Helper to remove item from slice
func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// GetEffectiveCsp returns a CSP suitable for a specific version/check logic.
// This implements the versions. For simplicity, we implement logic equivalent to "latest" checks
// handling strict-dynamic and nonces.
func (c *Csp) GetEffectiveCsp() *Csp {
	effective := NewCsp()
	// Deep copy
	for k, v := range c.Directives {
		dst := make([]string, len(v))
		copy(dst, v)
		effective.Directives[k] = dst
	}

	// Logic for script-src handling types like unsafe-inline with nonces...
	// We only care about script-directives for now
	scriptDirectives := []string{DirectiveScriptSrc, DirectiveScriptSrcAttr, DirectiveScriptSrcElem}

	for _, d := range scriptDirectives {
		effDir := effective.GetEffectiveDirective(d)
		values, ok := c.Directives[effDir]
		if !ok {
			continue
		}

		hasNonce := false
		hasHash := false
		hasStrictDynamic := false

		for _, v := range values {
			if strings.HasPrefix(v, "'nonce-") {
				hasNonce = true
			}
			if strings.HasPrefix(v, "'sha") {
				hasHash = true
			}
			if v == KeywordStrictDynamic {
				hasStrictDynamic = true
			}
		}

		effectiveValues := effective.Directives[effDir]

		// CSP2: Ignore unsafe-inline if nonce or hash is present
		if hasNonce || hasHash {
			effectiveValues = removeString(effectiveValues, KeywordUnsafeInline)
		}

		// CSP3: strict-dynamic
		if hasStrictDynamic {
			// If strict-dynamic is present, whitelist/host-source/scheme-source are ignored
			// unsafe-inline and self are also ignored
			var newValues []string
			for _, v := range effectiveValues {
				if v == KeywordStrictDynamic || strings.HasPrefix(v, "'") && v != KeywordSelf && v != KeywordUnsafeInline {
					newValues = append(newValues, v)
				}
				// Keywords like 'unsafe-eval' are kept.
				// Host sources (no quotes) are removed.
			}
			effectiveValues = newValues
		}
		effective.Directives[effDir] = effectiveValues
	}
	return effective
}

// CHECKS implementation

func CheckScriptUnsafeInline(parsed *Csp) []Finding {
	effectiveCsp := parsed.GetEffectiveCsp()
	var findings []Finding
	directives := effectiveCsp.GetEffectiveDirectives([]string{DirectiveScriptSrc, DirectiveScriptSrcAttr, DirectiveScriptSrcElem})

	for _, d := range directives {
		vals := effectiveCsp.Directives[d]
		for _, v := range vals {
			if v == KeywordUnsafeInline {
				findings = append(findings, Finding{
					Type:        TypeScriptUnsafeInline,
					Description: "'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers.",
					Severity:    SeverityHigh,
					Directive:   d,
					Value:       KeywordUnsafeInline,
				})
			}
			if v == KeywordUnsafeHashes {
				findings = append(findings, Finding{
					Type:        TypeScriptUnsafeHashes,
					Description: "'unsafe-hashes' allows the execution of unsafe in-page scripts... Please refactor.",
					Severity:    SeverityMediumMaybe,
					Directive:   d,
					Value:       KeywordUnsafeHashes,
				})
			}
		}
	}
	return findings
}

func CheckScriptUnsafeEval(parsed *Csp) []Finding {
	effectiveCsp := parsed.GetEffectiveCsp()
	var findings []Finding
	directives := effectiveCsp.GetEffectiveDirectives([]string{DirectiveScriptSrc, DirectiveScriptSrcAttr, DirectiveScriptSrcElem})

	for _, d := range directives {
		vals := effectiveCsp.Directives[d]
		for _, v := range vals {
			if v == KeywordUnsafeEval {
				findings = append(findings, Finding{
					Type:        TypeScriptUnsafeEval,
					Description: "'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().",
					Severity:    SeverityMediumMaybe,
					Directive:   d,
					Value:       KeywordUnsafeEval,
				})
			}
		}
	}
	return findings
}

func CheckPlainUrlSchemes(parsed *Csp) []Finding {
	// This check runs on parsed CSP (not effective), usually? TS uses effective directives but checks values.
	// We'll use GetEffectiveDirectives but check strict values.
	var findings []Finding
	directives := parsed.GetEffectiveDirectives(DirectivesCausingXss)

	for _, d := range directives {
		vals := parsed.Directives[d]
		for _, v := range vals {
			for _, scheme := range UrlSchemesCausingXss {
				if v == scheme {
					findings = append(findings, Finding{
						Type:        TypePlainUrlSchemes,
						Description: v + " URI in " + d + " allows the execution of unsafe scripts.",
						Severity:    SeverityHigh,
						Directive:   d,
						Value:       v,
					})
				}
			}
		}
	}
	return findings
}

func CheckWildcards(parsed *Csp) []Finding {
	var findings []Finding
	directives := parsed.GetEffectiveDirectives(DirectivesCausingXss)
	for _, d := range directives {
		vals := parsed.Directives[d]
		for _, v := range vals {
			urlStr := getSchemeFreeUrl(v)
			if urlStr == "*" {
				findings = append(findings, Finding{
					Type:        TypePlainWildcard,
					Description: d + " should not allow '*' as source",
					Severity:    SeverityHigh,
					Directive:   d,
					Value:       v,
				})
			}
		}
	}
	return findings
}

func CheckMissingDirectives(parsed *Csp) []Finding {
	var findings []Finding
	// Object Src
	objRestricted := false
	if _, ok := parsed.Directives[DirectiveObjectSrc]; ok {
		objRestricted = true
	} else if _, ok := parsed.Directives[DirectiveDefaultSrc]; ok {
		objRestricted = true
	}
	if !objRestricted {
		findings = append(findings, Finding{
			Type:        TypeMissingDirectives,
			Description: "Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to 'none'?",
			Severity:    SeverityHigh,
			Directive:   DirectiveObjectSrc,
		})
	}

	// Script Src
	scriptRestricted := false
	if _, ok := parsed.Directives[DirectiveScriptSrc]; ok {
		scriptRestricted = true
	} else if _, ok := parsed.Directives[DirectiveDefaultSrc]; ok {
		scriptRestricted = true
	}
	if !scriptRestricted {
		findings = append(findings, Finding{
			Type:        TypeMissingDirectives,
			Description: "script-src directive is missing.",
			Severity:    SeverityHigh,
			Directive:   DirectiveScriptSrc,
		})
	}

	// Base Uri
	// needsBaseUri logic: if policy has nonces or hashes with strict dynamic
	needsBaseUri := false
	// Check if any script directive has nonce/strict-dynamic
	// Simplified check
	scriptDirectives := []string{DirectiveScriptSrc}
	effScript := parsed.GetEffectiveDirectives(scriptDirectives)
	for _, d := range effScript {
		vals := parsed.Directives[d]
		for _, v := range vals {
			if strings.HasPrefix(v, "'nonce-") || (v == KeywordStrictDynamic) { // simplified
				needsBaseUri = true
			}
		}
	}

	if needsBaseUri {
		if _, ok := parsed.Directives[DirectiveBaseUri]; !ok {
			findings = append(findings, Finding{
				Type:        TypeMissingDirectives,
				Description: "Missing base-uri allows the injection of base tags...",
				Severity:    SeverityHigh,
				Directive:   DirectiveBaseUri,
			})
		}
	}

	return findings
}

// CheckIpSource checks for IP addresses
func CheckIpSource(parsed *Csp) []Finding {
	var findings []Finding
	// regex for roughly IPv4
	ipRegex := regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

	for d, vals := range parsed.Directives {
		for _, v := range vals {
			host := getHostname(v)
			if ipRegex.MatchString(host) {
				sev := SeverityInfo
				desc := d + " directive has an IP-Address as source: " + host + " (will be ignored by browsers!)."
				if host == "127.0.0.1" {
					desc = d + " directive allows localhost as source. Please remove in production."
				}
				findings = append(findings, Finding{
					Type:        TypeIpSource,
					Description: desc,
					Severity:    sev,
					Directive:   d,
					Value:       v,
				})
			}
		}
	}
	return findings
}

// CheckNonceLength ...
func CheckNonceLength(parsed *Csp) []Finding {
	var findings []Finding
	nonceRegex := regexp.MustCompile(`^'nonce-(.+)'$`)

	for d, vals := range parsed.Directives {
		for _, v := range vals {
			matches := nonceRegex.FindStringSubmatch(v)
			if len(matches) > 1 {
				if len(matches[1]) < 8 {
					findings = append(findings, Finding{
						Type:        TypeNonceLength,
						Description: "Nonces should be at least 8 characters long.",
						Severity:    SeverityMedium,
						Directive:   d,
						Value:       v,
					})
				}
				// Charset check skipped for brevity
			}
		}
	}
	return findings
}

// Helper functions for Checking Bypasses

func getSchemeFreeUrl(u string) string {
	u = regexp.MustCompile(`^\w[+\w.-]*://`).ReplaceAllString(u, "")
	u = strings.TrimPrefix(u, "//")
	return u
}

func getHostname(u string) string {
	// Hacky way to handle wildcards and schemeless URLs using Go's net/url
	// TS does: https:// + schemeFree + replace * with placeholder
	schemeFree := getSchemeFreeUrl(u)
	schemeFree = strings.ReplaceAll(schemeFree, ":*", "") // remove wildcard port
	schemeFree = strings.ReplaceAll(schemeFree, "*", "wildcard_placeholder")

	parsed, err := url.Parse("https://" + schemeFree)
	if err != nil {
		return ""
	}
	hostname := parsed.Hostname()
	return strings.ReplaceAll(hostname, "wildcard_placeholder", "*")
}

func matchWildcardUrls(cspUrlString string, listOfUrlStrings []string) string {
	// Return matching URL or empty string
	sFree := getSchemeFreeUrl(cspUrlString)
	sFree = strings.ReplaceAll(sFree, ":*", "")
	sFree = strings.ReplaceAll(sFree, "*", "wildcard_placeholder")

	cspUrl, err := url.Parse("https://" + sFree)
	if err != nil {
		return ""
	}

	host := strings.ToLower(cspUrl.Hostname())
	hostHasWildcard := strings.HasPrefix(host, "wildcard_placeholder.")
	wildcardFreeHost := strings.TrimPrefix(host, "wildcard_placeholder") // keep leading dot if present?
	// wait, wildcard_placeholder.example.com -> .example.com
	if hostHasWildcard {
		wildcardFreeHost = strings.TrimPrefix(host, "wildcard_placeholder")
	}

	path := cspUrl.Path
	hasPath := path != "" && path != "/"

	for _, uString := range listOfUrlStrings {
		uStringClean := uString
		if strings.HasPrefix(uString, "//") {
			uStringClean = "https:" + uString
		} else if !strings.Contains(uString, "://") {
			uStringClean = "https://" + uString
		}

		u, err := url.Parse(uStringClean)
		if err != nil {
			continue
		}

		domain := strings.ToLower(u.Hostname())

		if !strings.HasSuffix(domain, wildcardFreeHost) {
			continue
		}

		if !hostHasWildcard && host != domain {
			continue
		}

		if hasPath {
			if strings.HasSuffix(path, "/") {
				if !strings.HasPrefix(u.Path, path) {
					continue
				}
			} else {
				if u.Path != path {
					continue
				}
			}
		}
		return uString
	}
	return ""
}

func CheckScriptAllowlistBypass(parsed *Csp) []Finding {
	var findings []Finding
	effective := parsed.GetEffectiveDirectives([]string{DirectiveScriptSrc, DirectiveScriptSrcElem})

	for _, d := range effective {
		values := parsed.Directives[d]
		if contains(values, KeywordNone) {
			continue
		}

		evalPresent := contains(values, KeywordUnsafeEval)

		for _, v := range values {
			if v == KeywordSelf {
				findings = append(findings, Finding{
					Type:        TypeScriptAllowlistBypass,
					Description: "'self' can be problematic if you host JSONP, AngularJS or user uploaded files.",
					Severity:    SeverityMediumMaybe,
					Directive:   d,
					Value:       v,
				})
				continue
			}

			if strings.HasPrefix(v, "'") {
				continue
			}
			if isUrlScheme(v) || !strings.Contains(v, ".") {
				continue
			}

			// Match against Angular and JSONP
			var bypassDomain string
			var bypassTxt string

			// Angular
			if match := matchWildcardUrls("//"+getSchemeFreeUrl(v), AngularUrls); match != "" {
				bypassDomain = getHostname(match) // simplified
				bypassTxt += " Angular libraries"
			}

			// JSONP
			if match := matchWildcardUrls("//"+getSchemeFreeUrl(v), JsonpUrls); match != "" {
				// check eval requirement
				hostname := getHostname(match)
				evalRequired := contains(JsonpNeedsEval, hostname)

				if !evalRequired || evalPresent {
					if bypassDomain == "" {
						bypassDomain = hostname
					}
					if bypassTxt != "" {
						bypassTxt += " and"
					}
					bypassTxt += " JSONP endpoints"
				}
			}

			if bypassTxt != "" {
				findings = append(findings, Finding{
					Type:        TypeScriptAllowlistBypass,
					Description: bypassDomain + " is known to host" + bypassTxt + " which allow to bypass this CSP.",
					Severity:    SeverityHigh,
					Directive:   d,
					Value:       v,
				})
			} else {
				// No bypass found message (Severity 50)
				findings = append(findings, Finding{
					Type:        TypeScriptAllowlistBypass,
					Description: "No bypass found; make sure that this URL doesn't serve JSONP replies or Angular libraries.",
					Severity:    SeverityMediumMaybe,
					Directive:   d,
					Value:       v,
				})
			}
		}
	}
	return findings
}

func CheckFlashObjectAllowlistBypass(parsed *Csp) []Finding {
	var findings []Finding
	d := parsed.GetEffectiveDirective(DirectiveObjectSrc)
	values := parsed.Directives[d]

	pluginTypes, hasPluginTypes := parsed.Directives[DirectivePluginTypes]
	if hasPluginTypes && !contains(pluginTypes, "application/x-shockwave-flash") {
		return nil
	}

	for _, v := range values {
		if v == KeywordNone {
			return nil
		}

		if match := matchWildcardUrls("//"+getSchemeFreeUrl(v), FlashUrls); match != "" {
			findings = append(findings, Finding{
				Type:        TypeObjectAllowlistBypass,
				Description: getHostname(match) + " is known to host Flash files which allow to bypass this CSP.",
				Severity:    SeverityHigh,
				Directive:   d,
				Value:       v,
			})
		} else if d == DirectiveObjectSrc {
			findings = append(findings, Finding{
				Type:        TypeObjectAllowlistBypass,
				Description: "Can you restrict object-src to 'none' only?",
				Severity:    SeverityMediumMaybe,
				Directive:   d,
				Value:       v,
			})
		}
	}
	return findings
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
