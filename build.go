//go:build ignore

// Command build is a portable build/packaging helper for cproxy.
//
// It replaces the Makefile so the project builds the same way on Windows,
// macOS, and Linux: everything is plain Go and needs no make, tar, or zip.
//
// Usage:
//
//	go run build.go                 # build windows/amd64, linux/amd64, linux/arm64 into bin/
//	go run build.go -targets=windows  # build only the Windows binary
//	go run build.go release         # build + create archives in dist/
//	go run build.go test            # go test ./...
//	go run build.go vet             # go vet ./...
//	go run build.go fmt             # go fmt ./...
//	go run build.go clean           # remove bin/ and dist/
//	go run build.go version         # print the resolved version
//
// Flags:
//
//	-version 1.2.3   override the version (default: git describe, else 0.1.0)
//	-targets ...     comma separated: windows, linux, linux-arm64, darwin
//	-out bin         output directory for binaries
//	-dist dist       output directory for release archives
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultVersion = "0.1.0"

type target struct {
	key    string
	goos   string
	goarch string
	name   string // binary file name
}

var targets = []target{
	{key: "windows", goos: "windows", goarch: "amd64", name: "cproxy.exe"},
	{key: "linux", goos: "linux", goarch: "amd64", name: "cproxy-linux-amd64"},
	{key: "linux-arm64", goos: "linux", goarch: "arm64", name: "cproxy-linux-arm64"},
	{key: "darwin", goos: "darwin", goarch: "arm64", name: "cproxy-darwin-arm64"},
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	var (
		version = ""
		list    = "windows,linux,linux-arm64"
		outDir  = "bin"
		distDir = "dist"
		verb    bool
	)
	var command string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "-version="):
			version = strings.TrimPrefix(arg, "-version=")
		case arg == "-version":
			i++
			if i >= len(args) {
				return fmt.Errorf("-version needs a value")
			}
			version = args[i]
		case strings.HasPrefix(arg, "-targets="):
			list = strings.TrimPrefix(arg, "-targets=")
		case arg == "-targets":
			i++
			if i >= len(args) {
				return fmt.Errorf("-targets needs a value")
			}
			list = args[i]
		case strings.HasPrefix(arg, "-out="):
			outDir = strings.TrimPrefix(arg, "-out=")
		case strings.HasPrefix(arg, "-dist="):
			distDir = strings.TrimPrefix(arg, "-dist=")
		case arg == "-v":
			verb = true
		case arg == "-h" || arg == "--help" || arg == "help":
			usage()
			return nil
		case strings.HasPrefix(arg, "-"):
			return fmt.Errorf("unknown flag %q (try: go run build.go help)", arg)
		default:
			if command != "" {
				return fmt.Errorf("unexpected argument %q", arg)
			}
			command = arg
		}
	}
	if command == "" {
		command = "build"
	}
	if version == "" {
		version = detectVersion()
	}

	root, err := moduleRoot()
	if err != nil {
		return err
	}

	switch command {
	case "build":
		return buildAll(root, version, list, outDir, verb)
	case "release":
		if err := buildAll(root, version, list, outDir, verb); err != nil {
			return err
		}
		return releaseAll(root, version, list, outDir, distDir, verb)
	case "test":
		return runGo(root, verb, "test", "./...", "-count=1")
	case "vet":
		return runGo(root, verb, "vet", "./...")
	case "fmt":
		return runGo(root, verb, "fmt", "./...")
	case "clean":
		for _, dir := range []string{outDir, distDir} {
			if err := os.RemoveAll(filepath.Join(root, dir)); err != nil {
				return err
			}
			fmt.Printf("removed %s/\n", dir)
		}
		return nil
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: go run build.go help)", command)
	}
}

func usage() {
	fmt.Print(`cproxy build helper (no make required)

Usage:
  go run build.go [flags] [command]

Commands:
  build      build binaries into -out (default; the default command)
  release    build, then create .zip/.tar.gz archives in -dist
  test       go test ./...
  vet        go vet ./...
  fmt        go fmt ./...
  clean      remove -out and -dist
  version    print the resolved version
  help       show this message

Flags:
  -version X        version stamped into the binary (default: git describe, else ` + defaultVersion + `)
  -targets LIST     comma separated: windows, linux, linux-arm64, darwin
                    (default: windows,linux,linux-arm64)
  -out DIR          binary output directory (default: bin)
  -dist DIR         archive output directory (default: dist)
  -v                print every command
`)
}

// moduleRoot finds the directory containing go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found; run this from the repository")
		}
		dir = parent
	}
}

func detectVersion() string {
	out, err := exec.Command("git", "describe", "--tags", "--always", "--dirty").Output()
	if err != nil {
		return defaultVersion
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return defaultVersion
	}
	return strings.TrimPrefix(v, "v")
}

func selectedTargets(list string) ([]target, error) {
	want := map[string]bool{}
	for _, key := range strings.Split(list, ",") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		want[key] = true
	}
	var picked []target
	for _, t := range targets {
		if want[t.key] {
			picked = append(picked, t)
			delete(want, t.key)
		}
	}
	if len(want) > 0 {
		unknown := make([]string, 0, len(want))
		for k := range want {
			unknown = append(unknown, k)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("unknown target(s): %s (available: windows, linux, linux-arm64, darwin)", strings.Join(unknown, ", "))
	}
	if len(picked) == 0 {
		return nil, fmt.Errorf("-targets is empty")
	}
	return picked, nil
}

func buildAll(root, version, list, outDir string, verb bool) error {
	picked, err := selectedTargets(list)
	if err != nil {
		return err
	}
	absOut := filepath.Join(root, outDir)
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return err
	}
	ldflags := fmt.Sprintf("-s -w -X main.version=%s", version)
	for _, t := range picked {
		dest := filepath.Join(absOut, t.name)
		rel, err := filepath.Rel(root, dest)
		if err != nil {
			rel = dest
		}
		fmt.Printf("build %-14s %s -> %s\n", t.key, t.goos+"/"+t.goarch, filepath.ToSlash(rel))
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", dest, "./cmd/cproxy")
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"GOOS="+t.goos,
			"GOARCH="+t.goarch,
			"CGO_ENABLED=0",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if verb {
			fmt.Printf("  env GOOS=%s GOARCH=%s CGO_ENABLED=0 go build -trimpath -ldflags %q -o %s ./cmd/cproxy\n",
				t.goos, t.goarch, ldflags, filepath.ToSlash(rel))
		}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build %s: %w", t.key, err)
		}
	}
	return nil
}

// releaseAll bundles each binary with the docs and config examples.
func releaseAll(root, version, list, outDir, distDir string, verb bool) error {
	picked, err := selectedTargets(list)
	if err != nil {
		return err
	}
	absDist := filepath.Join(root, distDir)
	if err := os.MkdirAll(absDist, 0o755); err != nil {
		return err
	}

	for _, t := range picked {
		binPath := filepath.Join(root, outDir, t.name)
		if _, err := os.Stat(binPath); err != nil {
			return fmt.Errorf("missing %s; run the build command first", binPath)
		}
		base := fmt.Sprintf("cproxy_%s_%s_%s", version, t.goos, t.goarch)
		files := []string{
			"README.md",
			"configs/server.example.json",
			"configs/agent.example.json",
		}
		if t.goos == "linux" {
			files = append(files,
				"deploy/systemd/cproxy-server.service",
				"deploy/systemd/cproxy-agent.service",
				"docs/deploy-higobase-admin.md",
			)
		}

		if t.goos == "windows" {
			dest := filepath.Join(absDist, base+".zip")
			if err := writeZip(dest, root, binPath, base, files, verb); err != nil {
				return err
			}
			fmt.Printf("archive %s\n", filepath.ToSlash(mustRel(root, dest)))
			continue
		}
		dest := filepath.Join(absDist, base+".tar.gz")
		if err := writeTarGz(dest, root, binPath, "cproxy", files, verb); err != nil {
			return err
		}
		fmt.Printf("archive %s\n", filepath.ToSlash(mustRel(root, dest)))
	}
	return nil
}

func writeZip(dest, root, binPath, prefix string, extra []string, verb bool) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)

	if err := addZipFile(zw, binPath, prefix+"/"+filepath.Base(binPath)); err != nil {
		return err
	}
	for _, rel := range extra {
		src := filepath.Join(root, rel)
		if err := addZipFile(zw, src, prefix+"/"+filepath.ToSlash(rel)); err != nil {
			return err
		}
	}
	return zw.Close()
}

func addZipFile(zw *zip.Writer, src, name string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("add %s: %w", src, err)
	}
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func writeTarGz(dest, root, binPath, binName string, extra []string, verb bool) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	if err := addTarFile(tw, binPath, binName, 0o755); err != nil {
		return err
	}
	for _, rel := range extra {
		mode := int64(0o644)
		if err := addTarFile(tw, filepath.Join(root, rel), filepath.ToSlash(rel), mode); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addTarFile(tw *tar.Writer, src, name string, mode int64) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("add %s: %w", src, err)
	}
	hdr := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

func runGo(root string, verb bool, args ...string) error {
	fmt.Printf("go %s\n", strings.Join(args, " "))
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if verb {
		fmt.Printf("  workdir=%s\n", root)
	}
	return cmd.Run()
}

func mustRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
