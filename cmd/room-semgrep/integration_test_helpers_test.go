//go:build semgrep_integration

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var integrationSignals = []string{
	"SIGNAL_KIND_SECRET_LITERAL",
	"SIGNAL_KIND_DYNAMIC_SQL_WITH_UNTRUSTED_INPUT",
	"SIGNAL_KIND_UNTRUSTED_OUTBOUND_DESTINATION",
	"SIGNAL_KIND_RUST_PANIC_IN_REQUEST_PATH",
	"SIGNAL_KIND_RUST_COMMAND_WITH_UNTRUSTED_ARGUMENT",
	"SIGNAL_KIND_RUST_WEAK_RNG_FOR_SECRET",
	"SIGNAL_KIND_RUST_UNTRUSTED_PATH",
	"SIGNAL_KIND_RUST_BLOCKING_LOCK_ACROSS_AWAIT",
}

func integrationPaths(t *testing.T) (string, string) {
	t.Helper()
	core := os.Getenv("ROOM_SEMGREP_CORE")
	if core == "" {
		t.Fatal("ROOM_SEMGREP_CORE is required")
	}
	core, err := filepath.Abs(core)
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(core, "-version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(version)) != "semgrep-core version: "+semgrepCoreVersion {
		t.Fatalf("semgrep-core version = %q, error = %v", version, err)
	}
	config, err := filepath.Abs(filepath.Join("..", "..", "analyzers", "semgrep", "room.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return core, config
}

func newFileDiff(path, source string) []byte {
	lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	var diff strings.Builder
	fmt.Fprintf(&diff, "diff --git a/%s b/%s\n--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", path, path, path, len(lines))
	for _, line := range lines {
		diff.WriteByte('+')
		diff.WriteString(line)
		diff.WriteByte('\n')
	}
	return []byte(diff.String())
}
