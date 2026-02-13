package utils

import (
	"strings"
	"testing"
)

// TestOpenEventGetPathReturnsAbsolutePaths verifies that GetPath() always
// returns the kernel-resolved absolute path (FullPath) when available,
// regardless of the FullPathTracing flag. This is a regression test for
// the bug where relative openat() arguments like "46/task/46/fd" were
// stored instead of "/proc/46/task/46/fd".
func TestOpenEventGetPathReturnsAbsolutePaths(t *testing.T) {
	tests := []struct {
		name             string
		fullPath         string
		path             string // raw fname from syscall (may be relative)
		fullPathTracing  bool
		expectedPath     string
		expectAbsolute   bool
	}{
		{
			name:            "full path available, returns absolute",
			fullPath:        "/proc/46/task/46/fd",
			path:            "46/task/46/fd",
			fullPathTracing: false,
			expectedPath:    "/proc/46/task/46/fd",
			expectAbsolute:  true,
		},
		{
			name:            "full path available with tracing on",
			fullPath:        "/proc/46/task/46/fd",
			path:            "46/task/46/fd",
			fullPathTracing: true,
			expectedPath:    "/proc/46/task/46/fd",
			expectAbsolute:  true,
		},
		{
			name:            "dot path resolved to absolute",
			fullPath:        "/app/data",
			path:            ".",
			fullPathTracing: false,
			expectedPath:    "/app/data",
			expectAbsolute:  true,
		},
		{
			name:            "fallback to fname when fpath empty",
			fullPath:        "",
			path:            "/etc/passwd",
			fullPathTracing: false,
			expectedPath:    "/etc/passwd",
			expectAbsolute:  true,
		},
		{
			name:            "fallback to relative fname when fpath empty",
			fullPath:        "",
			path:            "relative/path",
			fullPathTracing: false,
			expectedPath:    "relative/path",
			expectAbsolute:  false, // unavoidable when gadget doesn't provide fpath
		},
		{
			name:            "both empty",
			fullPath:        "",
			path:            "",
			fullPathTracing: false,
			expectedPath:    "",
			expectAbsolute:  false,
		},
		{
			name:            "proc self fd resolved",
			fullPath:        "/proc/self/fd/3",
			path:            "fd/3",
			fullPathTracing: false,
			expectedPath:    "/proc/self/fd/3",
			expectAbsolute:  true,
		},
		{
			name:            "runc init path resolved",
			fullPath:        "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc123/rootfs",
			path:            ".",
			fullPathTracing: false,
			expectedPath:    "/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc123/rootfs",
			expectAbsolute:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &StructEvent{
				EventType:       OpenEventType,
				FullPath:        tt.fullPath,
				Path:            tt.path,
				FullPathTracing: tt.fullPathTracing,
			}

			got := event.GetPath()

			if got != tt.expectedPath {
				t.Errorf("GetPath() = %q, want %q", got, tt.expectedPath)
			}

			if tt.expectAbsolute && got != "" && !strings.HasPrefix(got, "/") {
				t.Errorf("GetPath() = %q, expected absolute path starting with /", got)
			}
		})
	}
}

// TestOpenEventGetPathIgnoresFullPathTracingFlag verifies that the
// FullPathTracing flag does NOT gate whether GetPath() uses the
// resolved path. This is a regression test: the old code only returned
// the full path when FullPathTracing was true.
func TestOpenEventGetPathIgnoresFullPathTracingFlag(t *testing.T) {
	event := &StructEvent{
		EventType:       OpenEventType,
		FullPath:        "/proc/1/status",
		Path:            "status",
		FullPathTracing: false,
	}

	got := event.GetPath()
	if got != "/proc/1/status" {
		t.Errorf("GetPath() with FullPathTracing=false returned %q, want %q (must not gate on flag)", got, "/proc/1/status")
	}
}
