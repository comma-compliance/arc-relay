package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/comma-compliance/arc-relay/internal/safefile"
)

const stateFileName = "state.json"

// State holds per-project state like skipped servers.
type State struct {
	Projects map[string]*ProjectState `json:"projects"`
}

// ProjectState holds the state for a single project.
type ProjectState struct {
	Skipped []string `json:"skipped"`
	// ServerIDs maps server ID to the slug name last synced.
	// Used to detect server renames between syncs.
	ServerIDs map[string]string `json:"server_ids,omitempty"`
}

// StatePath returns the full path to state.json within the given config directory.
func StatePath(configDir string) string {
	return filepath.Join(configDir, stateFileName)
}

// LoadState loads state from the given directory. Returns an empty state if the
// file doesn't exist.
func LoadState(configDir string) (*State, error) {
	data, err := safefile.ReadFile(configDir, stateFileName)
	if err != nil {
		// Return empty state on any read error — callers use
		// state, _ := LoadState() and would panic on nil.
		return &State{Projects: make(map[string]*ProjectState)}, nil
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		// Return empty state on malformed JSON rather than nil — callers
		// use state, _ := LoadState() and would panic on nil.
		return &State{Projects: make(map[string]*ProjectState)}, nil
	}

	if state.Projects == nil {
		state.Projects = make(map[string]*ProjectState)
	}

	return &state, nil
}

// SaveState writes the state to the given directory.
func SaveState(configDir string, state *State) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("creating config directory %s: %w", configDir, err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	data = append(data, '\n')

	path := StatePath(configDir)
	if err := safefile.WriteFile(configDir, stateFileName, data, 0600); err != nil {
		return fmt.Errorf("writing state %s: %w", path, err)
	}

	return nil
}

// GetSkipped returns the list of skipped server names for a project.
func (s *State) GetSkipped(projectDir string) []string {
	ps, ok := s.Projects[projectDir]
	if !ok {
		return nil
	}
	return ps.Skipped
}

// IsSkipped returns true if the given server name is skipped for the project.
func (s *State) IsSkipped(projectDir, serverName string) bool {
	for _, name := range s.GetSkipped(projectDir) {
		if name == serverName {
			return true
		}
	}
	return false
}

// AddSkipped adds a server to the skip list for a project.
func (s *State) AddSkipped(projectDir, serverName string) {
	if s.IsSkipped(projectDir, serverName) {
		return
	}
	ps, ok := s.Projects[projectDir]
	if !ok {
		ps = &ProjectState{}
		s.Projects[projectDir] = ps
	}
	ps.Skipped = append(ps.Skipped, serverName)
}

// RemoveSkipped removes a single server from the skip list for a project.
func (s *State) RemoveSkipped(projectDir, serverName string) {
	ps, ok := s.Projects[projectDir]
	if !ok {
		return
	}
	for i, name := range ps.Skipped {
		if name == serverName {
			ps.Skipped = append(ps.Skipped[:i], ps.Skipped[i+1:]...)
			return
		}
	}
}

// ClearSkipped removes the skip list for a project.
func (s *State) ClearSkipped(projectDir string) {
	delete(s.Projects, projectDir)
}

// TrackServer records the server ID to slug mapping for a project.
func (s *State) TrackServer(projectDir, serverID, serverName string) {
	ps, ok := s.Projects[projectDir]
	if !ok {
		ps = &ProjectState{}
		s.Projects[projectDir] = ps
	}
	if ps.ServerIDs == nil {
		ps.ServerIDs = make(map[string]string)
	}
	ps.ServerIDs[serverID] = serverName
}

// UntrackServer removes a server ID mapping for a project.
func (s *State) UntrackServer(projectDir, serverID string) {
	ps, ok := s.Projects[projectDir]
	if !ok {
		return
	}
	delete(ps.ServerIDs, serverID)
}

// GetTrackedName returns the last-known slug for a server ID in a project.
// Returns empty string if not tracked.
func (s *State) GetTrackedName(projectDir, serverID string) string {
	ps, ok := s.Projects[projectDir]
	if !ok {
		return ""
	}
	return ps.ServerIDs[serverID]
}

// GetTrackedServers returns the full ID-to-name mapping for a project.
func (s *State) GetTrackedServers(projectDir string) map[string]string {
	ps, ok := s.Projects[projectDir]
	if !ok {
		return nil
	}
	return ps.ServerIDs
}
