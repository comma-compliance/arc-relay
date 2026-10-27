package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/comma-compliance/arc-relay/internal/safego"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	dclient "github.com/moby/moby/client"
)

// Manager handles Docker container lifecycle for managed MCP servers.
type Manager struct {
	cli         *dclient.Client
	networkName string
}

// NewManager creates a Docker manager connected to the given socket.
func NewManager(socket, networkName string) (*Manager, error) {
	var opts []dclient.Opt
	if socket != "" {
		opts = append(opts, dclient.WithHost(socket))
	}

	// Create a temporary client to discover the daemon's API version,
	// then recreate with that version pinned. This avoids the SDK's
	// minimum version check rejecting older daemons (e.g. Unraid's Docker 24).
	probe, err := dclient.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}
	ping, err := probe.Ping(context.Background(), dclient.PingOptions{})
	if err == nil && ping.APIVersion != "" {
		slog.Info("docker daemon API version", "version", ping.APIVersion)
		opts = append(opts, dclient.WithVersion(ping.APIVersion))
	} else {
		slog.Warn("docker ping failed, using default API version", "error", err)
	}
	_ = probe.Close()

	cli, err := dclient.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating docker client: %w", err)
	}

	m := &Manager{cli: cli, networkName: networkName}

	if err := m.ensureNetwork(context.Background()); err != nil {
		slog.Warn("could not ensure docker network", "network", networkName, "error", err)
	}

	return m, nil
}

func (m *Manager) ensureNetwork(ctx context.Context) error {
	result, err := m.cli.NetworkList(ctx, dclient.NetworkListOptions{})
	if err != nil {
		return err
	}
	for _, n := range result.Items {
		if n.Name == m.networkName {
			return nil
		}
	}
	_, err = m.cli.NetworkCreate(ctx, m.networkName, dclient.NetworkCreateOptions{
		Driver: "bridge",
	})
	return err
}

// PullImage pulls a Docker image.
func (m *Manager) PullImage(ctx context.Context, ref string) error {
	resp, err := m.cli.ImagePull(ctx, ref, dclient.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling image %s: %w", ref, err)
	}
	defer func() { _ = resp.Close() }()

	// Docker returns pull errors (e.g. "manifest not found") as JSON
	// objects in the response stream, not as HTTP errors. We must parse
	// the stream to detect them - same approach as parseBuildOutput.
	if err := parsePullOutput(resp); err != nil {
		return fmt.Errorf("pulling image %s: %w", ref, err)
	}
	return nil
}

// parsePullOutput reads the Docker pull JSON stream and checks for errors.
// Docker streams progress as JSON lines like {"status":"Pulling from ..."}
// and reports failures as {"error":"manifest unknown","errorDetail":{...}}.
func parsePullOutput(reader io.Reader) error {
	decoder := json.NewDecoder(reader)
	for {
		var msg struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if msg.Error != "" {
			return fmt.Errorf("%s", msg.Error)
		}
		if msg.Status != "" {
			slog.Debug("docker pull", "status", msg.Status)
		}
	}
}

// EnsureImage checks if an image exists locally, and pulls it if not.
func (m *Manager) EnsureImage(ctx context.Context, ref string) error {
	_, err := m.cli.ImageInspect(ctx, ref)
	if err == nil {
		return nil // image exists locally
	}
	return m.PullImage(ctx, ref)
}

// ContainerConfig holds the parameters for creating a container.
type ContainerConfig struct {
	Name       string
	Image      string
	Entrypoint []string // overrides image ENTRYPOINT
	Command    []string
	Env        map[string]string
	Port       int // 0 for stdio servers
}

// StartContainer creates and starts a container. Returns the container ID.
func (m *Manager) StartContainer(ctx context.Context, cfg ContainerConfig) (string, error) {
	env := make([]string, 0, len(cfg.Env))
	for k, v := range cfg.Env {
		env = append(env, k+"="+v)
	}

	containerCfg := &container.Config{
		Image:     cfg.Image,
		Env:       env,
		OpenStdin: cfg.Port == 0,
		Tty:       false,
	}
	if len(cfg.Entrypoint) > 0 {
		containerCfg.Entrypoint = cfg.Entrypoint
	}
	if len(cfg.Command) > 0 {
		containerCfg.Cmd = cfg.Command
	}

	hostCfg := &container.HostConfig{}
	networkCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			m.networkName: {},
		},
	}

	if cfg.Port > 0 {
		port := network.MustParsePort(fmt.Sprintf("%d/tcp", cfg.Port))
		containerCfg.ExposedPorts = network.PortSet{
			port: {},
		}
		hostCfg.PortBindings = network.PortMap{
			port: []network.PortBinding{
				{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "0"},
			},
		}
	}

	containerName := "arc-relay-" + cfg.Name

	// Remove any leftover container with the same name (e.g. from a previous run
	// that wasn't cleaned up, or from a relay restart).
	_, _ = m.cli.ContainerRemove(ctx, containerName, dclient.ContainerRemoveOptions{Force: true})

	createResult, err := m.cli.ContainerCreate(ctx, dclient.ContainerCreateOptions{
		Config:           containerCfg,
		HostConfig:       hostCfg,
		NetworkingConfig: networkCfg,
		Name:             containerName,
	})
	if err != nil {
		return "", fmt.Errorf("creating container %s: %w", containerName, err)
	}

	if _, err := m.cli.ContainerStart(ctx, createResult.ID, dclient.ContainerStartOptions{}); err != nil {
		_, _ = m.cli.ContainerRemove(ctx, createResult.ID, dclient.ContainerRemoveOptions{Force: true})
		return "", fmt.Errorf("starting container %s: %w", containerName, err)
	}

	return createResult.ID, nil
}

// StopContainer stops and removes a container.
func (m *Manager) StopContainer(ctx context.Context, containerID string) error {
	timeout := 10
	if _, err := m.cli.ContainerStop(ctx, containerID, dclient.ContainerStopOptions{Timeout: &timeout}); err != nil {
		slog.Warn("error stopping container", "container", containerID, "error", err)
	}
	_, err := m.cli.ContainerRemove(ctx, containerID, dclient.ContainerRemoveOptions{Force: true})
	return err
}

// AttachStdio attaches to a running container's stdin/stdout.
// The Docker stream is multiplexed (8-byte header per frame) when TTY=false,
// so we demux stdout into a clean pipe for JSON-RPC communication.
func (m *Manager) AttachStdio(ctx context.Context, containerID string) (io.WriteCloser, io.ReadCloser, error) {
	resp, err := m.cli.ContainerAttach(ctx, containerID, dclient.ContainerAttachOptions{
		Stdin:  true,
		Stdout: true,
		Stderr: true,
		Stream: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attaching to container %s: %w", containerID, err)
	}

	// Demux the Docker multiplexed stream into clean stdout/stderr pipes
	stdoutR, stdoutW := io.Pipe()
	go func() {
		defer safego.Recover("docker demux")
		_, err := stdcopy.StdCopy(stdoutW, io.Discard, resp.Reader)
		if err != nil {
			slog.Error("docker demux error", "container", containerID[:12], "error", err)
		}
		_ = stdoutW.Close()
	}()

	return resp.Conn, stdoutR, nil
}

// GetHostPort returns the host port mapped to the given container port.
func (m *Manager) GetHostPort(ctx context.Context, containerID string, containerPort int) (string, error) {
	result, err := m.cli.ContainerInspect(ctx, containerID, dclient.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspecting container %s: %w", containerID, err)
	}
	port := network.MustParsePort(fmt.Sprintf("%d/tcp", containerPort))
	bindings, ok := result.Container.NetworkSettings.Ports[port]
	if !ok || len(bindings) == 0 {
		return "", fmt.Errorf("no host port mapping for %d/tcp in container %s", containerPort, containerID)
	}
	return bindings[0].HostPort, nil
}

// IsRunning checks if a container is running.
func (m *Manager) IsRunning(ctx context.Context, containerID string) (bool, error) {
	result, err := m.cli.ContainerInspect(ctx, containerID, dclient.ContainerInspectOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "No such container") {
			return false, nil
		}
		return false, err
	}
	return result.Container.State.Running, nil
}

// WaitForHTTP waits for a container to be running.
func (m *Manager) WaitForHTTP(ctx context.Context, containerID string, timeout time.Duration) error {
	deadline := time.After(timeout)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-deadline:
			return fmt.Errorf("timeout waiting for container %s", containerID)
		case <-tick.C:
			running, err := m.IsRunning(ctx, containerID)
			if err != nil {
				return err
			}
			if running {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ImageExists checks if a Docker image exists locally.
func (m *Manager) ImageExists(ctx context.Context, ref string) bool {
	_, err := m.cli.ImageInspect(ctx, ref)
	return err == nil
}

// BuildImage builds a Docker image from a Dockerfile string.
// The Dockerfile is sent as a tar archive to the Docker build API.
func (m *Manager) BuildImage(ctx context.Context, dockerfile string, tag string, noCache bool) error {
	// Create a tar archive containing just the Dockerfile
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	header := &tar.Header{
		Name: "Dockerfile",
		Size: int64(len(dockerfile)),
		Mode: 0644,
	}
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("writing tar header: %w", err)
	}
	if _, err := tw.Write([]byte(dockerfile)); err != nil {
		return fmt.Errorf("writing tar body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing tar: %w", err)
	}

	result, err := m.cli.ImageBuild(ctx, &buf, dclient.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: "Dockerfile",
		Remove:     true,
		NoCache:    noCache,
	})
	if err != nil {
		return fmt.Errorf("building image %s: %w", tag, err)
	}
	defer func() { _ = result.Body.Close() }()

	// Read the build output to completion and check for errors
	if err := parseBuildOutput(result.Body); err != nil {
		return fmt.Errorf("building image %s: %w", tag, err)
	}

	return nil
}

// BuildImageFromContext builds a Docker image from a directory context.
// It streams a tar archive of the directory to the Docker build API.
// Symlinks are preserved (never dereferenced), .git/ is skipped, and
// .dockerignore is respected if present.
func (m *Manager) BuildImageFromContext(ctx context.Context, contextDir, dockerfilePath, tag string, noCache bool) error {
	pr, pw := io.Pipe()

	// Parse .dockerignore if present
	ignorePatterns := parseDockerignore(contextDir)

	go func() {
		defer safego.Recover("docker build context")
		tw := tar.NewWriter(pw)
		err := tarDirectory(tw, contextDir, ignorePatterns)
		_ = tw.Close()
		pw.CloseWithError(err)
	}()

	result, err := m.cli.ImageBuild(ctx, pr, dclient.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: dockerfilePath,
		Remove:     true,
		NoCache:    noCache,
	})
	if err != nil {
		return fmt.Errorf("building image %s: %w", tag, err)
	}
	defer func() { _ = result.Body.Close() }()

	if err := parseBuildOutput(result.Body); err != nil {
		return fmt.Errorf("building image %s: %w", tag, err)
	}

	return nil
}

// parseBuildOutput reads Docker build JSON stream and checks for errors.
func parseBuildOutput(reader io.Reader) error {
	decoder := json.NewDecoder(reader)
	for {
		var msg struct {
			Stream string `json:"stream"`
			Error  string `json:"error"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if msg.Error != "" {
			return fmt.Errorf("%s", msg.Error)
		}
		if msg.Stream != "" {
			slog.Debug("docker build output", "line", strings.TrimRight(msg.Stream, "\n"))
		}
	}
}

// Dockerfile templates for auto-building from packages.
var dockerfileTemplates = map[string]*template.Template{
	"python": template.Must(template.New("python").Parse(`FROM python:3.11-slim
RUN pip install --no-cache-dir {{.Package}}{{if .Version}}=={{.Version}}{{end}}
`)),
	"node": template.Must(template.New("node").Parse(`FROM node:20-slim
RUN npm install -g {{.Package}}{{if .Version}}@{{.Version}}{{end}}
ENTRYPOINT ["npx"]
CMD ["{{.Package}}"]
`)),
	"git-python": template.Must(template.New("git-python").Parse(`FROM python:3.11-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone {{.GitURL}} /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || pip install --no-cache-dir .
`)),
	"git-node": template.Must(template.New("git-node").Parse(`FROM node:20-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone {{.GitURL}} /app
WORKDIR /app
RUN npm install
`)),
}

// BuildConfig holds the template data for Dockerfile generation.
type BuildConfig struct {
	Runtime string
	Package string
	Version string
	GitURL  string
}

// GenerateDockerfile creates a Dockerfile from a build config.
// If a custom Dockerfile is provided, it is returned as-is.
func GenerateDockerfile(runtime, pkg, version, gitURL, customDockerfile string) (string, error) {
	if customDockerfile != "" {
		return customDockerfile, nil
	}

	data := BuildConfig{
		Runtime: runtime,
		Package: pkg,
		Version: version,
		GitURL:  gitURL,
	}

	var tmplKey string
	if gitURL != "" {
		tmplKey = "git-" + runtime
	} else {
		tmplKey = runtime
	}

	tmpl, ok := dockerfileTemplates[tmplKey]
	if !ok {
		return "", fmt.Errorf("unsupported build template: %s", tmplKey)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("executing dockerfile template: %w", err)
	}
	return buf.String(), nil
}

// ImageInfo holds metadata from a Docker image inspection.
type ImageInfo struct {
	ID      string    // content-addressable image ID (sha256:...)
	Created time.Time // image creation timestamp
	Size    int64     // total image size in bytes
	Tags    []string  // repo tags referencing this image
}

// InspectImage returns metadata for a Docker image.
func (m *Manager) InspectImage(ctx context.Context, ref string) (*ImageInfo, error) {
	result, err := m.cli.ImageInspect(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("inspecting image %s: %w", ref, err)
	}
	info := &ImageInfo{
		ID:   result.ID,
		Size: result.Size,
		Tags: result.RepoTags,
	}
	if result.Created != "" {
		if t, err := time.Parse(time.RFC3339Nano, result.Created); err == nil {
			info.Created = t
		}
	}
	return info, nil
}

// GetContainerImageID returns the image ID that the container was created with.
func (m *Manager) GetContainerImageID(ctx context.Context, containerID string) (string, error) {
	result, err := m.cli.ContainerInspect(ctx, containerID, dclient.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspecting container %s: %w", containerID, err)
	}
	return result.Container.Image, nil
}

func (m *Manager) Close() error {
	return m.cli.Close()
}

// tarDirectory walks a directory and writes its contents as a tar stream.
// It skips .git/ directories, rejects paths with ".." segments, and
// preserves symlinks without dereferencing them.
func tarDirectory(tw *tar.Writer, root string, ignorePatterns []string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get path relative to root
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		// Use forward slashes for Docker
		relPath = filepath.ToSlash(relPath)

		// Reject path traversal
		for _, part := range strings.Split(relPath, "/") {
			if part == ".." {
				return fmt.Errorf("path traversal detected: %s", relPath)
			}
		}

		// Skip .git directory
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}

		// Check dockerignore patterns
		if shouldIgnore(relPath, info.IsDir(), ignorePatterns) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Handle symlinks — preserve as symlinks, never dereference
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("reading symlink %s: %w", relPath, err)
			}
			header := &tar.Header{
				Typeflag: tar.TypeSymlink,
				Name:     relPath,
				Linkname: target,
				Mode:     int64(info.Mode().Perm()),
				ModTime:  info.ModTime(),
			}
			return tw.WriteHeader(header)
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("creating tar header for %s: %w", relPath, err)
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("writing tar header for %s: %w", relPath, err)
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path) // #nosec G122 G304 - symlinks handled above (line 515), path is from local git repo context
		if err != nil {
			return fmt.Errorf("opening %s: %w", relPath, err)
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
}

// parseDockerignore reads a .dockerignore file and returns the patterns.
func parseDockerignore(contextDir string) []string {
	f, err := os.Open(filepath.Join(contextDir, ".dockerignore")) // #nosec G304 - contextDir is server-controlled build context
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// shouldIgnore checks if a path matches any dockerignore pattern.
func shouldIgnore(relPath string, isDir bool, patterns []string) bool {
	for _, pattern := range patterns {
		negate := false
		p := pattern
		if strings.HasPrefix(p, "!") {
			negate = true
			p = p[1:]
		}
		// Match against the path
		matched, _ := filepath.Match(p, relPath)
		if !matched {
			// Also try matching against the base name
			matched, _ = filepath.Match(p, filepath.Base(relPath))
		}
		if !matched && isDir {
			// Try matching directory patterns like "dir/"
			matched, _ = filepath.Match(strings.TrimSuffix(p, "/"), relPath)
		}
		if matched {
			return !negate
		}
	}
	return false
}
