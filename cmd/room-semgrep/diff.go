package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$`)

type diffArtifact struct {
	added     map[string]map[int]bool
	expected  map[string]map[int]string
	files     map[string]bool
	deleted   map[string]bool
	postimage map[string]bool
}

func (artifact diffArtifact) paths() []string {
	paths := make([]string, 0, len(artifact.files))
	for path := range artifact.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func parseDiff(diff []byte) (diffArtifact, error) {
	artifact := diffArtifact{added: make(map[string]map[int]bool), expected: make(map[string]map[int]string), files: make(map[string]bool), deleted: make(map[string]bool), postimage: make(map[string]bool)}
	if len(diff) == 0 {
		return artifact, nil
	}
	path, oldPath, sectionPath, newLine := "", "", "", 0
	oldRemaining, newRemaining := 0, 0
	inHunk, sawSection, sawOld, sawTarget, sawHunk := false, false, false, false, false
	for _, raw := range bytes.Split(diff, []byte("\n")) {
		line := string(raw)
		if inHunk && oldRemaining == 0 && newRemaining == 0 {
			inHunk = false
		}
		if !inHunk {
			if strings.HasPrefix(line, "diff --git ") {
				if sawSection && !sawHunk {
					return diffArtifact{}, errors.New("diff section has no hunks")
				}
				fields := strings.Fields(line)
				if len(fields) != 4 {
					return diffArtifact{}, errors.New("diff header is invalid")
				}
				oldHeaderPath, oldOK := parseSidePath(fields[2], "a/")
				newHeaderPath, newOK := parseSidePath(fields[3], "b/")
				if !oldOK || !newOK || oldHeaderPath != newHeaderPath {
					return diffArtifact{}, errors.New("renames and malformed diff headers are unsupported")
				}
				path, oldPath, sectionPath, sawOld, sawTarget, sawHunk = "", "", oldHeaderPath, false, false, false
				sawSection = true
				continue
			}
			if strings.HasPrefix(line, "--- ") {
				if !sawSection || sawOld {
					return diffArtifact{}, errors.New("source header is invalid")
				}
				oldPath, _ = parseSidePath(strings.TrimPrefix(line, "--- "), "a/")
				if oldPath == "" && line != "--- /dev/null" {
					return diffArtifact{}, errors.New("source path is invalid")
				}
				if oldPath != "" && oldPath != sectionPath {
					return diffArtifact{}, errors.New("source path does not match diff header")
				}
				sawOld = true
				continue
			}
			if strings.HasPrefix(line, "+++ ") {
				if !sawOld || sawTarget {
					return diffArtifact{}, errors.New("target header is invalid")
				}
				targetDeleted := line == "+++ /dev/null"
				path, _ = parseSidePath(strings.TrimPrefix(line, "+++ "), "b/")
				sawTarget = true
				if path == "" && line != "+++ /dev/null" {
					return diffArtifact{}, errors.New("target path is invalid")
				}
				if path == "" {
					path = oldPath
				}
				if path != sectionPath || (oldPath == "" && targetDeleted) {
					return diffArtifact{}, errors.New("target path does not match diff header")
				}
				if !validRelativePath(path) || artifact.files[path] {
					return diffArtifact{}, errors.New("target path is invalid or duplicated")
				}
				artifact.files[path] = true
				if targetDeleted {
					artifact.deleted[path] = true
				} else {
					artifact.postimage[path] = true
				}
				continue
			}
			if match := hunkHeader.FindStringSubmatch(line); match != nil {
				if !sawTarget {
					return diffArtifact{}, errors.New("hunk has no target")
				}
				var err error
				oldRemaining, err = hunkCount(match[2])
				if err != nil {
					return diffArtifact{}, errors.New("hunk count is invalid")
				}
				newLine, err = strconv.Atoi(match[3])
				if err != nil {
					return diffArtifact{}, errors.New("hunk line is invalid")
				}
				newRemaining, err = hunkCount(match[4])
				if err != nil {
					return diffArtifact{}, errors.New("hunk count is invalid")
				}
				inHunk, sawHunk = true, true
				continue
			}
			if line == "" || strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode ") || strings.HasPrefix(line, "old mode ") || strings.HasPrefix(line, "new mode ") {
				continue
			}
			return diffArtifact{}, errors.New("unexpected diff content")
		}
		if line == `\ No newline at end of file` {
			continue
		}
		if line == "" {
			return diffArtifact{}, errors.New("truncated hunk")
		}
		switch line[0] {
		case ' ':
			if oldRemaining == 0 || newRemaining == 0 || path == "" {
				return diffArtifact{}, errors.New("invalid context line")
			}
			setExpected(artifact.expected, path, newLine, line[1:])
			oldRemaining--
			newRemaining--
			newLine++
		case '+':
			if newRemaining == 0 || path == "" {
				return diffArtifact{}, errors.New("invalid added line")
			}
			setExpected(artifact.expected, path, newLine, line[1:])
			if artifact.added[path] == nil {
				artifact.added[path] = make(map[int]bool)
			}
			artifact.added[path][newLine] = true
			newRemaining--
			newLine++
		case '-':
			if oldRemaining == 0 {
				return diffArtifact{}, errors.New("invalid removed line")
			}
			oldRemaining--
		default:
			return diffArtifact{}, errors.New("invalid hunk line")
		}
	}
	if inHunk && (oldRemaining != 0 || newRemaining != 0) {
		return diffArtifact{}, errors.New("truncated hunk")
	}
	if !sawHunk || !sawSection {
		return diffArtifact{}, errors.New("no unified diff hunks")
	}
	return artifact, nil
}

func hunkCount(value string) (int, error) {
	if value == "" {
		return 1, nil
	}
	count, err := strconv.Atoi(value)
	return count, err
}

func setExpected(expected map[string]map[int]string, path string, line int, content string) {
	if expected[path] == nil {
		expected[path] = make(map[int]string)
	}
	expected[path][line] = content
}

func verifyPostimage(data []byte, expected map[int]string) error {
	lines := bytes.Split(data, []byte("\n"))
	for line, content := range expected {
		if line < 1 || line > len(lines) || string(lines[line-1]) != content {
			return errors.New("diff does not match repository postimage")
		}
	}
	return nil
}

func parseSidePath(value, prefix string) (string, bool) {
	value = strings.SplitN(value, "\t", 2)[0]
	if !strings.HasPrefix(value, prefix) || strings.HasPrefix(value, `"`) || strings.TrimSpace(value) != value {
		return "", false
	}
	path := strings.TrimPrefix(value, prefix)
	return path, validRelativePath(path)
}

func validRelativePath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return path != "" && !filepath.IsAbs(path) && clean == path && clean != ".." && !strings.HasPrefix(clean, "../")
}

func normalizedResultPath(directory, path string) (string, error) {
	if filepath.IsAbs(path) {
		relative, err := filepath.Rel(directory, path)
		if err != nil || strings.HasPrefix(filepath.ToSlash(relative), "../") {
			return "", errors.New("result path outside snapshot")
		}
		path = relative
	}
	path = filepath.ToSlash(filepath.Clean(path))
	if !validRelativePath(path) {
		return "", errors.New("result path invalid")
	}
	return path, nil
}

func rangeIntersects(lines map[int]bool, start, end int) bool {
	if start < 1 || end < start {
		return false
	}
	for line := range lines {
		if line >= start && line <= end {
			return true
		}
	}
	return false
}

func evidenceDigest(directory, path string, start, end int) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(path)))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	lines := bytes.Split(data, []byte("\n"))
	if start < 1 || end < start || end > len(lines) {
		return [sha256.Size]byte{}, errors.New("finding range outside target")
	}
	return sha256.Sum256(bytes.Join(lines[start-1:end], []byte("\n"))), nil
}

func metadataConfidence(metadata map[string]any) (uint32, bool) {
	value, ok := metadata["room_confidence_basis_points"]
	if !ok {
		return 0, false
	}
	var confidence uint64
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, false
		}
		confidence = uint64(typed)
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 32)
		if err != nil {
			return 0, false
		}
		confidence = parsed
	default:
		return 0, false
	}
	return uint32(confidence), confidence > 0 && confidence <= 10_000
}
