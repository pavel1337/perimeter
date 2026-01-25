package csp

// Severity represents the severity of a finding.
type Severity int

const (
	SeverityHigh        Severity = 10
	SeveritySyntax      Severity = 20
	SeverityMedium      Severity = 30
	SeverityHighMaybe   Severity = 40
	SeverityStrictCSP   Severity = 45
	SeverityMediumMaybe Severity = 50
	SeverityInfo        Severity = 60
	SeverityNone        Severity = 100
)

// Type represents the type of a finding.
type Type int

const (
	// Parser checks
	TypeMissingSemicolon Type = 100
	TypeUnknownDirective Type = 101
	TypeInvalidKeyword   Type = 102
	TypeNonceCharset     Type = 106

	// Security checks
	TypeMissingDirectives      Type = 300
	TypeScriptUnsafeInline     Type = 301
	TypeScriptUnsafeEval       Type = 302
	TypePlainUrlSchemes        Type = 303
	TypePlainWildcard          Type = 304
	TypeScriptAllowlistBypass  Type = 305
	TypeObjectAllowlistBypass  Type = 306
	TypeNonceLength            Type = 307
	TypeIpSource               Type = 308
	TypeDeprecatedDirective    Type = 309
	TypeSrcHttp                Type = 310
	TypeSrcNoProtocol          Type = 311
	TypeExperimental           Type = 312
	TypeWildcardUrl            Type = 313
	TypeXFrameOptionsObsoleted Type = 314
	TypeStyleUnsafeInline      Type = 315
	TypeStaticNonce            Type = 316
	TypeScriptUnsafeHashes     Type = 317

	// Strict dynamic and backward compatibility checks
	TypeStrictDynamic              Type = 400
	TypeStrictDynamicNotStandalone Type = 401
	TypeNonceHash                  Type = 402
	TypeUnsafeInlineFallback       Type = 403
	TypeAllowlistFallback          Type = 404
	TypeIgnored                    Type = 405

	// Trusted Types checks
	TypeRequireTrustedTypesForScripts Type = 500

	// Lighthouse checks
	TypeReportingDestinationMissing Type = 600
	TypeReportToOnly                Type = 601
)

// Finding represents a CSP finding.
type Finding struct {
	Type        Type     `json:"type"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Directive   string   `json:"directive"`
	Value       string   `json:"value,omitempty"`
}
