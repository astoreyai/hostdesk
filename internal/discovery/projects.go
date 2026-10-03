package discovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/astoreyai/hostdesk/internal/model"
)

var skippedProjectDirectories = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, ".hg": true, ".svn": true,
	".cache": true, "__pycache__": true, ".venv": true, "venv": true, "env": true,
	"dist": true, "build": true, "target": true, "coverage": true, ".next": true,
	".nuxt": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
}

func projectManifest(name string) string {
	switch name {
	case "go.mod":
		return "Go"
	case "package.json":
		return "JavaScript/TypeScript"
	case "Cargo.toml":
		return "Rust"
	case "pyproject.toml", "setup.py", "requirements.txt", "Pipfile":
		return "Python"
	case "Gemfile":
		return "Ruby"
	case "composer.json":
		return "PHP"
	case "pom.xml", "build.gradle", "build.gradle.kts":
		return "JVM"
	case "CMakeLists.txt", "Makefile", "meson.build":
		return "Native"
	case "mix.exs":
		return "Elixir"
	case "pubspec.yaml":
		return "Dart"
	case "Package.swift":
		return "Swift"
	case "flake.nix":
		return "Nix"
	case "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml":
		return "Compose"
	}
	if strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".fsproj") {
		return ".NET"
	}
	return ""
}

func hostDirectory(value string) string {
	value = strings.TrimLeft(value, "-!")
	if !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}

func collectProjects(ctx context.Context, roots []string, services []model.Service) ([]model.Project, model.Source) {
	s := source("projects", nil)
	projects := []model.Project{}
	rootSet := map[string]bool{}
	orderedRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		if path := hostDirectory(root); path != "" && path != "/" {
			if !rootSet[path] {
				rootSet[path] = true
				orderedRoots = append(orderedRoots, path)
			}
		} else {
			partial(&s, "a project root is not a permitted absolute directory")
		}
	}
	derivedRoots := []string{}
	for _, service := range services {
		if service.Manager != "systemd" {
			continue
		}
		if path := hostDirectory(service.WorkingDirectory); path != "" && path != "/" && !rootSet[path] {
			rootSet[path] = true
			derivedRoots = append(derivedRoots, path)
		}
	}
	// Explicit scan roots take precedence over broad inferred working directories.
	// Otherwise a home-directory service can exhaust the budget before user roots.
	sort.Strings(derivedRoots)
	explicitCount := len(orderedRoots)
	orderedRoots = append(orderedRoots, derivedRoots...)
	if len(orderedRoots) == 0 {
		partial(&s, "no project roots or host service working directories configured")
		return projects, s
	}
	visited := map[string]bool{}
	directories, entriesSeen, denied, missing := 0, 0, 0, 0
	depthCapped, totalCapped := false, false
	type scanDirectory struct {
		path  string
		depth int
	}
	queue := []scanDirectory{}
	scan := func(path string, depth int) {
		if visited[path] || totalCapped || ctx.Err() != nil {
			return
		}
		if directories >= 20000 || entriesSeen >= 200000 || len(projects) >= 4096 {
			totalCapped = true
			return
		}
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				missing++
			} else {
				denied++
			}
			return
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return
		}
		visited[path] = true
		directories++
		dir, err := os.Open(path)
		if err != nil {
			denied++
			return
		}
		children := []string{}
		kinds, git := map[string]bool{}, false
		for {
			entries, readErr := dir.ReadDir(256)
			for _, entry := range entries {
				entriesSeen++
				if entriesSeen > 200000 {
					totalCapped = true
					break
				}
				name := entry.Name()
				if name == ".git" && entry.Type()&os.ModeSymlink == 0 {
					git = true
				}
				if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
					if kind := projectManifest(name); kind != "" {
						kinds[kind] = true
					}
				}
				if entry.IsDir() && !skippedProjectDirectories[name] && !strings.HasPrefix(name, ".") {
					children = append(children, filepath.Join(path, name))
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					denied++
				}
				break
			}
			if totalCapped {
				break
			}
		}
		dir.Close()
		if git || len(kinds) > 0 {
			labels := []string{}
			for kind := range kinds {
				labels = append(labels, kind)
			}
			sort.Strings(labels)
			kind := strings.Join(labels, ", ")
			if kind == "" {
				kind = "Git"
			}
			digest := sha256.Sum256([]byte(path))
			projects = append(projects, model.Project{ID: fmt.Sprintf("project:%x", digest[:12]), Name: filepath.Base(path), Path: path, Kind: kind, Git: git, ServiceIDs: []string{}})
		}
		if depth >= 6 {
			if len(children) > 0 {
				depthCapped = true
			}
			return
		}
		sort.Strings(children)
		for _, child := range children {
			queue = append(queue, scanDirectory{child, depth + 1})
		}
	}
	// Breadth-first traversal finds neighboring project roots before descending
	// into one large archive. Explicit roots are a separate higher-priority group.
	for _, group := range [][]string{orderedRoots[:explicitCount], orderedRoots[explicitCount:]} {
		queue = queue[:0]
		for _, root := range group {
			queue = append(queue, scanDirectory{root, 0})
		}
		for next := 0; next < len(queue) && !totalCapped && ctx.Err() == nil; next++ {
			directory := queue[next]
			scan(directory.path, directory.depth)
		}
	}
	for _, service := range services {
		if service.Manager != "systemd" {
			continue
		}
		path := hostDirectory(service.WorkingDirectory)
		best := -1
		for i := range projects {
			if path == projects[i].Path || strings.HasPrefix(path, projects[i].Path+string(filepath.Separator)) {
				if best < 0 || len(projects[i].Path) > len(projects[best].Path) {
					best = i
				}
			}
		}
		if best >= 0 {
			projects[best].ServiceIDs = append(projects[best].ServiceIDs, service.ID)
		}
	}
	if directories == 0 && denied > 0 {
		s.Available = false
	}
	if denied > 0 {
		partial(&s, "some directories could not be read")
	}
	if missing > 0 {
		partial(&s, "some configured or service working directories no longer exist")
	}
	if depthCapped {
		partial(&s, "recursive scan limited to six directory levels per root")
	}
	if totalCapped {
		partial(&s, "project scan reached its directory, entry or project cap")
	}
	if ctx.Err() != nil {
		partial(&s, "project scan canceled")
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Path < projects[j].Path })
	return projects, s
}
