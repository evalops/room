package mcp

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	roomv1 "github.com/haasonsaas/room/gen/go/room/v1"
	"github.com/haasonsaas/room/internal/agentclient"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type Handler struct {
	client *agentclient.Client
}

func NewHandler(serverURL string) http.Handler {
	h := &Handler{
		client: agentclient.New(strings.TrimRight(serverURL, "/"), agentclient.DefaultCachePath()),
	}
	return mcpsdk.NewStreamableHTTPHandler(func(_ *http.Request) *mcpsdk.Server {
		return h.server()
	}, nil)
}

func (h *Handler) server() *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "room",
		Version: "dev",
	}, &mcpsdk.ServerOptions{
		Instructions: "Room provides coding-agent security guardrails. Call room_analyze_plan before implementation choices and room_check_diff after edits.",
	})

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_get_rules",
		Description: "Fetch the active Room ruleset for this repository and agent context.",
	}, h.getRules)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_analyze_plan",
		Description: "Analyze an intended implementation plan against the active security ruleset before writing code.",
	}, h.analyzePlan)

	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        "room_check_diff",
		Description: "Analyze a proposed or completed diff against the active security ruleset.",
	}, h.checkDiff)

	return server
}

type ruleInput struct {
	WorkspaceID  string   `json:"workspace_id,omitempty" jsonschema:"Workspace or organization identifier"`
	Repository   string   `json:"repository,omitempty" jsonschema:"Repository name or slug"`
	AgentType    string   `json:"agent_type,omitempty" jsonschema:"Coding agent type, such as codex, claude-code, cursor"`
	CWD          string   `json:"cwd,omitempty" jsonschema:"Current working directory"`
	ChangedFiles []string `json:"changed_files,omitempty" jsonschema:"Files the agent expects to change"`
}

type planInput struct {
	ruleInput
	Plan string `json:"plan" jsonschema:"required,The implementation plan or decision the coding agent is about to make"`
}

type diffInput struct {
	ruleInput
	Diff string `json:"diff" jsonschema:"required,Unified diff or patch text to evaluate"`
}

type toolOutput struct {
	Decision        string        `json:"decision,omitempty"`
	Blocking        bool          `json:"blocking"`
	HighestSeverity string        `json:"highest_severity,omitempty"`
	Summary         string        `json:"summary"`
	Matches         []matchOutput `json:"matches,omitempty"`
	RequiredChecks  []string      `json:"required_checks,omitempty"`
	RulesetID       string        `json:"ruleset_id,omitempty"`
	RulesetVersion  int32         `json:"ruleset_version,omitempty"`
	RulesetHash     string        `json:"ruleset_hash,omitempty"`
	RuleCount       int           `json:"rule_count,omitempty"`
	Rules           []ruleOutput  `json:"rules,omitempty"`
}

type matchOutput struct {
	RuleID           string   `json:"rule_id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Message          string   `json:"message"`
	Tags             []string `json:"tags,omitempty"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	Remediation      []string `json:"remediation,omitempty"`
}

type ruleOutput struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
}

func (h *Handler) getRules(ctx context.Context, _ *mcpsdk.CallToolRequest, input ruleInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	ruleset, err := h.client.ActiveRuleset(ctx, input.context())
	if err != nil {
		return nil, toolOutput{}, err
	}
	output := rulesetOutput(ruleset)
	return textResult(output.Summary), output, nil
}

func (h *Handler) analyzePlan(ctx context.Context, _ *mcpsdk.CallToolRequest, input planInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	result, err := h.client.EvaluatePlan(ctx, &roomv1.EvaluationInput{Context: input.context(), Plan: input.Plan})
	if err != nil {
		return nil, toolOutput{}, err
	}
	output := evaluationOutput(result)
	return textResult(output.Summary), output, nil
}

func (h *Handler) checkDiff(ctx context.Context, _ *mcpsdk.CallToolRequest, input diffInput) (*mcpsdk.CallToolResult, toolOutput, error) {
	result, err := h.client.EvaluateDiff(ctx, &roomv1.EvaluationInput{Context: input.context(), Diff: input.Diff})
	if err != nil {
		return nil, toolOutput{}, err
	}
	output := evaluationOutput(result)
	return textResult(output.Summary), output, nil
}

func (i ruleInput) context() *roomv1.EvaluationContext {
	return &roomv1.EvaluationContext{
		WorkspaceId:  i.WorkspaceID,
		Repository:   i.Repository,
		AgentType:    i.AgentType,
		Cwd:          i.CWD,
		ChangedFiles: append([]string(nil), i.ChangedFiles...),
	}
}

func rulesetOutput(ruleset *roomv1.RulesetVersion) toolOutput {
	if ruleset == nil {
		return toolOutput{Summary: "Room has no active ruleset."}
	}
	rules := make([]ruleOutput, 0, len(ruleset.GetRules()))
	for _, rule := range ruleset.GetRules() {
		rules = append(rules, ruleOutput{
			ID:       rule.GetId(),
			Title:    rule.GetTitle(),
			Severity: severityString(rule.GetSeverity()),
			Tags:     append([]string(nil), rule.GetTags()...),
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	summary := fmt.Sprintf("Room active ruleset %s v%d contains %d rule(s).", ruleset.GetId(), ruleset.GetVersion(), len(rules))
	return toolOutput{
		Blocking:       false,
		Summary:        summary,
		RulesetID:      ruleset.GetId(),
		RulesetVersion: ruleset.GetVersion(),
		RulesetHash:    ruleset.GetHash(),
		RuleCount:      len(rules),
		Rules:          rules,
	}
}

func evaluationOutput(result *roomv1.EvaluationResult) toolOutput {
	if result == nil {
		return toolOutput{Decision: "allow", Blocking: false, Summary: "Room decision: allow. No result returned."}
	}
	matches := make([]matchOutput, 0, len(result.GetMatches()))
	for _, match := range result.GetMatches() {
		matches = append(matches, matchOutput{
			RuleID:           match.GetRuleId(),
			Title:            match.GetTitle(),
			Severity:         severityString(match.GetSeverity()),
			Message:          match.GetMessage(),
			Tags:             append([]string(nil), match.GetTags()...),
			RequiredEvidence: append([]string(nil), match.GetRequiredEvidence()...),
			Remediation:      append([]string(nil), match.GetRemediation()...),
		})
	}
	decision := decisionString(result.GetDecision())
	output := toolOutput{
		Decision:        decision,
		Blocking:        result.GetDecision() == roomv1.Decision_DECISION_DENY || result.GetDecision() == roomv1.Decision_DECISION_NEEDS_CHANGES,
		HighestSeverity: severityString(result.GetHighestSeverity()),
		Matches:         matches,
		RequiredChecks:  append([]string(nil), result.GetRequiredChecks()...),
		RulesetID:       result.GetRulesetId(),
		RulesetVersion:  result.GetRulesetVersion(),
		RulesetHash:     result.GetRulesetHash(),
	}
	output.Summary = summarizeEvaluation(output)
	return output
}

func summarizeEvaluation(output toolOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Room decision: %s", output.Decision)
	if output.HighestSeverity != "" && output.HighestSeverity != "unspecified" {
		fmt.Fprintf(&b, " (%s)", output.HighestSeverity)
	}
	if output.RulesetVersion > 0 {
		fmt.Fprintf(&b, " using ruleset v%d", output.RulesetVersion)
	}
	b.WriteString(".")
	if len(output.Matches) == 0 {
		b.WriteString(" No guardrails matched.")
		return b.String()
	}
	fmt.Fprintf(&b, " Matched %d rule(s):", len(output.Matches))
	for _, match := range output.Matches {
		fmt.Fprintf(&b, "\n- %s [%s]: %s", match.RuleID, match.Severity, match.Message)
	}
	if len(output.RequiredChecks) > 0 {
		b.WriteString("\nRequired evidence:")
		for _, check := range output.RequiredChecks {
			fmt.Fprintf(&b, "\n- %s", check)
		}
	}
	return b.String()
}

func textResult(text string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: text}},
	}
}

func decisionString(decision roomv1.Decision) string {
	switch decision {
	case roomv1.Decision_DECISION_ALLOW:
		return "allow"
	case roomv1.Decision_DECISION_WARN:
		return "warn"
	case roomv1.Decision_DECISION_NEEDS_CHANGES:
		return "needs_changes"
	case roomv1.Decision_DECISION_DENY:
		return "deny"
	default:
		return "unspecified"
	}
}

func severityString(severity roomv1.Severity) string {
	switch severity {
	case roomv1.Severity_SEVERITY_INFO:
		return "info"
	case roomv1.Severity_SEVERITY_LOW:
		return "low"
	case roomv1.Severity_SEVERITY_MEDIUM:
		return "medium"
	case roomv1.Severity_SEVERITY_HIGH:
		return "high"
	case roomv1.Severity_SEVERITY_CRITICAL:
		return "critical"
	default:
		return "unspecified"
	}
}
