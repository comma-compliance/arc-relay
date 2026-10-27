package config

import (
	"testing"
	"time"
)

func TestLLMConfigTimeoutDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5m", 5 * time.Minute},
		{"90s", 90 * time.Second},
		{"600", 600 * time.Second},
		{"nonsense", 0},
	}
	for _, tt := range tests {
		got := LLMConfig{Timeout: tt.in}.TimeoutDuration()
		if got != tt.want {
			t.Errorf("TimeoutDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
