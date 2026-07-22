package hunt

// Severity classifies a confirmed authorization finding.
type Severity string

// Severity levels for hunt findings.
const (
	SeverityHigh     Severity = "high"     // read access to another user's object
	SeverityCritical Severity = "critical" // reserved for sensitive-data BOLA
)

// Finding is a confirmed broken-object-level-authorization (IDOR/BOLA) result:
// one identity read another identity's object through a request that should
// have been denied.
type Finding struct {
	RequestID string
	Endpoint  string // the concrete URL tested
	Method    string
	Attacker  string // identity whose session was used
	Victim    string // identity whose object was accessed
	ObjectID  string
	Status    int
	Severity  Severity
	Evidence  string // why this is a real leak, not a coincidental 200
}

// PlanStep is one request the engine would issue, with its scope decision —
// used by --dry-run to show exactly what will (and will not) be contacted
// before anything is sent.
type PlanStep struct {
	RequestID string
	Method    string
	URL       string
	Identity  string
	Kind      string // "baseline" or "cross-account"
	InScope   bool
}

// Report is the outcome of a hunt run.
type Report struct {
	Program           string
	Findings          []Finding
	TestsRun          int // cross-account authorization tests actually sent
	BaselinesRun      int
	OutOfScopeSkipped int
	Errors            []string
}
