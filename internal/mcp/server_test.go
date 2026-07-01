package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haasonsaas/room/internal/app"
	"github.com/haasonsaas/room/internal/server"
	"github.com/haasonsaas/room/internal/store"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAnalyzePlanFlagsUnsafePlanThroughMCP(t *testing.T) {
	t.Setenv("ROOM_CACHE_FILE", filepath.Join(t.TempDir(), "ruleset.json"))
	ruleStore, err := store.Open(filepath.Join(t.TempDir(), "room.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	roomServer := httptest.NewServer(server.New(app.New(ruleStore)))
	defer roomServer.Close()

	mcpServer := httptest.NewServer(NewHandler(roomServer.URL))
	defer mcpServer.Close()

	ctx := context.Background()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "room-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: mcpServer.URL}, nil)
	if err != nil {
		t.Fatalf("connect mcp client: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if !hasTool(tools, "room_analyze_plan") {
		t.Fatalf("room_analyze_plan not listed: %#v", tools.Tools)
	}

	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "room_analyze_plan",
		Arguments: map[string]any{
			"plan":          "Add a customer endpoint that queries projects from the database.",
			"changed_files": []string{"internal/api/projects.go"},
			"agent_type":    "codex",
		},
	})
	if err != nil {
		t.Fatalf("call room_analyze_plan: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned protocol error content: %#v", result.Content)
	}
	text := firstText(result)
	if !strings.Contains(text, "Room decision: deny") {
		t.Fatalf("tool text = %q, want Room decision: deny", text)
	}
	if !strings.Contains(text, "tenant-org-scope-required") {
		t.Fatalf("tool text = %q, want tenant-org-scope-required", text)
	}

	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var structured struct {
		Decision string `json:"decision"`
		Blocking bool   `json:"blocking"`
	}
	if err := json.Unmarshal(data, &structured); err != nil {
		t.Fatalf("unmarshal structured content: %v", err)
	}
	if structured.Decision != "deny" || !structured.Blocking {
		t.Fatalf("structured = %+v, want deny blocking", structured)
	}
}

func hasTool(result *mcpsdk.ListToolsResult, name string) bool {
	for _, tool := range result.Tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func firstText(result *mcpsdk.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := content.(*mcpsdk.TextContent); ok {
			return text.Text
		}
	}
	return ""
}
