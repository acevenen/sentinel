package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/acevenen/sentinel/internal/hunt"
)

// Hunt output formats.
const (
	HuntFormatTerminal = "terminal"
	HuntFormatJSON     = "json"
	HuntFormatMarkdown = "markdown" // HackerOne-ready reproduction reports
)

// RenderHunt writes a hunt report in the requested format.
func RenderHunt(w io.Writer, format string, r hunt.Report) error {
	switch format {
	case HuntFormatJSON:
		return renderHuntJSON(w, r)
	case HuntFormatMarkdown:
		return renderHuntMarkdown(w, r)
	case HuntFormatTerminal, "":
		return renderHuntTerminal(w, r)
	default:
		return fmt.Errorf("unknown format %q (want terminal, json, or markdown)", format)
	}
}

func renderHuntJSON(w io.Writer, r hunt.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// RenderHuntPlan prints the requests a run would issue and their scope
// decisions, without sending anything (for --dry-run).
func RenderHuntPlan(w io.Writer, program string, steps []hunt.PlanStep) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	bold.Fprintf(w, "\nSentinel Hunt — dry run (%s)\n", program)
	dim.Fprintf(w, "%s\n", strings.Repeat("─", 72))
	dim.Fprintf(w, "  No requests are sent. Each line shows the scope decision.\n\n")

	var refused int
	for _, s := range steps {
		mark := color.GreenString("in-scope")
		if !s.InScope {
			mark = color.New(color.FgHiRed, color.Bold).Sprint("OUT-OF-SCOPE (refused)")
			refused++
		}
		fmt.Fprintf(w, "  %-13s %-6s %-9s as %-8s  %s\n", s.Kind, s.Method, mark, s.Identity, s.URL)
	}
	fmt.Fprintf(w, "\n  %d request(s) planned, %d refused as out of scope.\n\n", len(steps), refused)
}

func renderHuntTerminal(w io.Writer, r hunt.Report) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)

	bold.Fprintf(w, "\nSentinel Hunt — IDOR/BOLA\n")
	dim.Fprintf(w, "%s\n", strings.Repeat("─", 64))
	fmt.Fprintf(w, "  Program            %s\n", r.Program)
	fmt.Fprintf(w, "  Authorization tests %d\n", r.TestsRun)
	fmt.Fprintf(w, "  Baselines           %d\n", r.BaselinesRun)
	if r.OutOfScopeSkipped > 0 {
		fmt.Fprintf(w, "  Out-of-scope refused %d\n", r.OutOfScopeSkipped)
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintf(w, "  ✓ No broken object-level authorization found in the tested endpoints.\n\n")
	} else {
		color.New(color.FgHiRed, color.Bold).Fprintf(w, "  ✗ %d BOLA/IDOR finding(s)\n", len(r.Findings))
		dim.Fprintf(w, "  %s\n", strings.Repeat("─", 64))
		for _, f := range r.Findings {
			color.New(color.FgHiRed, color.Bold).Fprintf(w, "  [%s] %s\n", strings.ToUpper(string(f.Severity)), f.RequestID)
			fmt.Fprintf(w, "  %s %s\n", f.Method, f.Endpoint)
			fmt.Fprintf(w, "  %s → %s's object %s\n", f.Attacker, f.Victim, f.ObjectID)
			fmt.Fprintf(w, "  %s\n\n", f.Evidence)
		}
	}

	for _, e := range r.Errors {
		color.New(color.FgYellow).Fprintf(w, "  warning: %s\n", e)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintln(w)
	}
	return nil
}

// renderHuntMarkdown emits a HackerOne-ready report per finding.
func renderHuntMarkdown(w io.Writer, r hunt.Report) error {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "# Sentinel Hunt — %s\n\nNo broken object-level authorization found in the tested endpoints.\n", r.Program)
		return nil
	}

	fmt.Fprintf(w, "# Sentinel Hunt — %s\n\n%d IDOR/BOLA finding(s). Each section below is a draft report; verify manually before submitting.\n\n", r.Program, len(r.Findings))

	for i, f := range r.Findings {
		fmt.Fprintf(w, "---\n\n## Finding %d — Broken Object Level Authorization (%s)\n\n", i+1, strings.ToUpper(string(f.Severity)))
		fmt.Fprintf(w, "**Endpoint:** `%s %s`\n\n", f.Method, f.Endpoint)
		fmt.Fprintf(w, "**Weakness:** Insecure Direct Object Reference / Broken Object Level Authorization (CWE-639, OWASP API1:2023)\n\n")

		fmt.Fprintf(w, "### Summary\n\n")
		fmt.Fprintf(w, "The `%s` endpoint returns an object without verifying that the requesting identity is authorized to access it. Using the session of test account `%s`, it was possible to read object `%s`, which belongs to a different test account (`%s`).\n\n",
			f.RequestID, f.Attacker, f.ObjectID, f.Victim)

		fmt.Fprintf(w, "### Steps to Reproduce\n\n")
		fmt.Fprintf(w, "1. Authenticate as test account **%s** and note the object `%s` it owns.\n", f.Victim, f.ObjectID)
		fmt.Fprintf(w, "2. Authenticate as a separate test account **%s**.\n", f.Attacker)
		fmt.Fprintf(w, "3. Using **%s**'s session, request the victim's object:\n\n", f.Attacker)
		fmt.Fprintf(w, "   ```\n   %s %s\n   Authorization: <%s's session>\n   ```\n\n", f.Method, f.Endpoint, f.Attacker)
		fmt.Fprintf(w, "4. Observe **HTTP %d** with the response body byte-identical to %s's own response for object `%s` — %s received another user's object.\n\n",
			f.Status, f.Victim, f.ObjectID, f.Attacker)

		fmt.Fprintf(w, "### Impact\n\n")
		fmt.Fprintf(w, "Any authenticated user can read other users' objects by changing the object identifier, exposing data across account boundaries.\n\n")

		fmt.Fprintf(w, "### Remediation\n\n")
		fmt.Fprintf(w, "Enforce object-level authorization on the server: verify the authenticated principal owns (or is otherwise entitled to) the requested object before returning it. Do not rely on the object identifier being unguessable.\n\n")
	}
	return nil
}
