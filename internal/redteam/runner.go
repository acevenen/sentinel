package redteam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/acevenen/sentinel/internal/authz"
	"github.com/acevenen/sentinel/internal/tools"
)

const defaultResponseLimit = 2 << 20

var requestFieldPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

// Probe is operator-supplied test content classified by the shared taxonomy.
// Sentinel deliberately ships no embedded probe payloads.
type Probe struct {
	ID                     string   `json:"id"`
	CategoryID             string   `json:"category_id"`
	Delivery               Delivery `json:"delivery"`
	Content                string   `json:"content"`
	FailIfResponseContains []string `json:"fail_if_response_contains,omitempty"`
}

// Suite is an operator-reviewed set of probes for one request schema.
type Suite struct {
	Name         string  `json:"name"`
	RequestField string  `json:"request_field"`
	Probes       []Probe `json:"probes"`
}

// LoadSuiteFile decodes and strictly validates a suite's JSON shape. Taxonomy
// validation occurs in Runner so custom catalogs can be supplied.
func LoadSuiteFile(path string) (Suite, error) {
	file, err := os.Open(path)
	if err != nil {
		return Suite{}, fmt.Errorf("opening red-team suite: %w", err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, 8<<20))
	decoder.DisallowUnknownFields()
	var suite Suite
	if err := decoder.Decode(&suite); err != nil {
		return Suite{}, fmt.Errorf("decoding red-team suite: %w", err)
	}
	if strings.TrimSpace(suite.Name) == "" || !requestFieldPattern.MatchString(suite.RequestField) {
		return Suite{}, errors.New("suite requires a name and a simple request_field")
	}
	if len(suite.Probes) == 0 {
		return Suite{}, errors.New("suite contains no probes")
	}
	return suite, nil
}

// HTTPDoer is the narrow client contract used for deterministic testing.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Runner executes approved probes sequentially through the authorization gate.
type Runner struct {
	Guard         authz.Guardrail
	Auditor       tools.Auditor
	Client        HTTPDoer
	Taxonomy      Taxonomy
	ResponseLimit int64
}

// RunOptions are the per-run safety controls and accountable identity.
type RunOptions struct {
	Target       string
	EngagementID string
	Operator     string
	Mode         TargetMode
	Approved     bool
	DryRun       bool
}

// ProbeStatus is a classification, not proof of exploitability.
type ProbeStatus string

const (
	StatusResisted ProbeStatus = "resisted"
	StatusFailed   ProbeStatus = "failed"
	StatusSkipped  ProbeStatus = "skipped"
	StatusManual   ProbeStatus = "manual-review"
	StatusPlanned  ProbeStatus = "planned"
)

// ProbeResult intentionally excludes probe and response contents.
type ProbeResult struct {
	ID         string      `json:"id"`
	CategoryID string      `json:"category_id"`
	Delivery   Delivery    `json:"delivery"`
	Status     ProbeStatus `json:"status"`
	Detail     string      `json:"detail,omitempty"`
	HTTPStatus int         `json:"http_status,omitempty"`
	Duration   string      `json:"duration,omitempty"`
}

// RunResult is a prompt-free classification report.
type RunResult struct {
	Suite   string        `json:"suite"`
	Target  string        `json:"target"`
	Mode    TargetMode    `json:"target_mode"`
	DryRun  bool          `json:"dry_run"`
	Results []ProbeResult `json:"results"`
}

// Run validates, authorizes, audits, and executes the suite.
func (r Runner) Run(ctx context.Context, suite Suite, options RunOptions) (RunResult, error) {
	if !options.Approved {
		return RunResult{}, errors.New("operator approval is required; pass --approve-probes after reviewing the suite")
	}
	if options.Mode != TargetBlackBox && options.Mode != TargetLocal {
		return RunResult{}, fmt.Errorf("unsupported target mode %q", options.Mode)
	}
	if err := validateEndpoint(options.Target); err != nil {
		return RunResult{}, err
	}
	if r.Guard == nil {
		return RunResult{}, errors.New("red-team guardrail is required")
	}
	if r.Auditor == nil {
		return RunResult{}, errors.New("red-team auditor is required")
	}
	if r.Client == nil {
		r.Client = http.DefaultClient
	}
	if len(r.Taxonomy.Categories) == 0 {
		return RunResult{}, errors.New("red-team taxonomy is required")
	}
	if err := validateSuite(suite, r.Taxonomy); err != nil {
		return RunResult{}, err
	}
	limit := r.ResponseLimit
	if limit <= 0 {
		limit = defaultResponseLimit
	}
	report := RunResult{Suite: suite.Name, Target: options.Target, Mode: options.Mode, DryRun: options.DryRun}
	for _, probe := range suite.Probes {
		category, _ := r.Taxonomy.ByID(probe.CategoryID)
		if options.Mode == TargetBlackBox && category.WhiteBoxOnly {
			report.Results = append(report.Results, ProbeResult{
				ID: probe.ID, CategoryID: probe.CategoryID, Delivery: probe.Delivery,
				Status: StatusSkipped, Detail: "category requires locally controlled model access",
			})
			continue
		}
		action := authz.Action{
			Operator:     options.Operator,
			EngagementID: options.EngagementID,
			Target:       options.Target,
			Tool:         "ai-redteam",
			Arguments:    []string{"probe=" + probe.ID, "category=" + probe.CategoryID},
			Active:       true,
		}
		if err := r.Guard.Authorize(ctx, action); err != nil {
			_ = r.audit(ctx, action, options.DryRun, "refused: "+err.Error())
			return report, fmt.Errorf("ai-redteam authorization refused: %w", err)
		}
		if options.DryRun {
			if err := r.audit(ctx, action, true, "planned"); err != nil {
				return report, err
			}
			report.Results = append(report.Results, ProbeResult{
				ID: probe.ID, CategoryID: probe.CategoryID, Delivery: probe.Delivery, Status: StatusPlanned,
			})
			continue
		}
		if err := r.audit(ctx, action, false, "execution started"); err != nil {
			return report, err
		}
		result, err := r.execute(ctx, suite.RequestField, options.Target, probe, limit)
		if err != nil {
			_ = r.audit(ctx, action, false, "execution failed: "+err.Error())
			return report, err
		}
		report.Results = append(report.Results, result)
		if err := r.audit(ctx, action, false, "completed: "+string(result.Status)); err != nil {
			return report, err
		}
	}
	return report, nil
}

func validateSuite(suite Suite, taxonomy Taxonomy) error {
	if strings.TrimSpace(suite.Name) == "" || !requestFieldPattern.MatchString(suite.RequestField) {
		return errors.New("suite requires a name and a simple request_field")
	}
	seen := map[string]bool{}
	for _, probe := range suite.Probes {
		if strings.TrimSpace(probe.ID) == "" || seen[probe.ID] {
			return fmt.Errorf("probe ids must be non-empty and unique: %q", probe.ID)
		}
		seen[probe.ID] = true
		if strings.TrimSpace(probe.Content) == "" {
			return fmt.Errorf("probe %q has empty operator-supplied content", probe.ID)
		}
		category, ok := taxonomy.ByID(probe.CategoryID)
		if !ok {
			return fmt.Errorf("probe %q references unknown category %q", probe.ID, probe.CategoryID)
		}
		if probe.Delivery != DeliveryDirect && probe.Delivery != DeliveryIndirect {
			return fmt.Errorf("probe %q must choose direct or indirect delivery", probe.ID)
		}
		if category.Delivery != DeliveryBoth && category.Delivery != probe.Delivery {
			return fmt.Errorf("probe %q delivery %q conflicts with category delivery %q", probe.ID, probe.Delivery, category.Delivery)
		}
		for _, indicator := range probe.FailIfResponseContains {
			if strings.TrimSpace(indicator) == "" {
				return fmt.Errorf("probe %q contains an empty response indicator", probe.ID)
			}
		}
	}
	return nil
}

func validateEndpoint(target string) error {
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("ai-redteam target must be an absolute http(s) URL")
	}
	if parsed.User != nil {
		return errors.New("ai-redteam target must not contain URL credentials")
	}
	return nil
}

func (r Runner) execute(
	ctx context.Context,
	requestField string,
	target string,
	probe Probe,
	limit int64,
) (ProbeResult, error) {
	body, err := json.Marshal(map[string]string{requestField: probe.Content})
	if err != nil {
		return ProbeResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return ProbeResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	start := time.Now()
	response, err := r.Client.Do(request)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("sending approved probe %q: %w", probe.ID, err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return ProbeResult{}, fmt.Errorf("reading response for probe %q: %w", probe.ID, err)
	}
	if int64(len(data)) > limit {
		return ProbeResult{}, fmt.Errorf("response for probe %q exceeded %d bytes", probe.ID, limit)
	}
	result := ProbeResult{
		ID: probe.ID, CategoryID: probe.CategoryID, Delivery: probe.Delivery,
		Status: StatusResisted, HTTPStatus: response.StatusCode,
		Duration: time.Since(start).Round(time.Millisecond).String(),
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		result.Status = StatusManual
		result.Detail = "target returned a non-success HTTP status"
		return result, nil
	}
	responseText := strings.ToLower(string(data))
	for _, indicator := range probe.FailIfResponseContains {
		if strings.Contains(responseText, strings.ToLower(indicator)) {
			result.Status = StatusFailed
			result.Detail = "operator-defined failure indicator matched"
			break
		}
	}
	return result, nil
}

func (r Runner) audit(ctx context.Context, action authz.Action, dryRun bool, result string) error {
	decision := "allowed"
	if strings.HasPrefix(result, "refused:") {
		decision = "refused"
	}
	return r.Auditor.Record(ctx, tools.AuditEvent{
		Timestamp:     time.Now().UTC(),
		Operator:      action.Operator,
		EngagementID:  action.EngagementID,
		Target:        action.Target,
		Tool:          action.Tool,
		Arguments:     append([]string(nil), action.Arguments...),
		ScopeDecision: decision,
		Result:        result,
		DryRun:        dryRun,
	})
}
