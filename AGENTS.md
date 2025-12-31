# Repository Guidelines

## Project Structure & Module Organization
- `main.go` is the entrypoint; it wires CLI execution via `cmd/`.
- `cmd/` contains Cobra commands and subcommands (e.g., `cmd/connect.go`, `cmd/tui/`).
- `pkg/crackstation/` holds core crackstation coordination logic; `pkg/hashcat/` wraps the hashcat CLI and platform-specific implementations.
- `assets/` stores bundled hashcat archives by OS/arch; `go-assets.sh` regenerates these. Generated assets live under `assets/{darwin,linux,windows}/...`.
- `util/` includes shared helpers (zip/files). `vendor/` is a vendored dependency tree used by `-mod=vendor` builds.

## Build, Test, and Development Commands
- `make` (default target) builds the `sliver-crackstation` binary using vendored deps.
- `make macos`, `make macos-arm64`, `make linux`, `make windows` produce OS-specific binaries.
- `make clean` removes local build artifacts; `make clean-all` also removes packaged assets.
- `./go-assets.sh` downloads hashcat archives into `assets/` (requires `curl`, `zip`, `unzip`, `tar`, and network access).
- `go test ./...` can be used for a quick compile/test pass even though no tests exist yet.

## Coding Style & Naming Conventions
- Use standard Go formatting (`gofmt`/`goimports`); keep packages lowercase and file names descriptive.
- Platform-specific code follows Go’s suffix convention (e.g., `*_windows.go`, `*_darwin.go`, `*_linux.go`).
- Keep exported types and functions in `PascalCase`, unexported in `camelCase`.

## Testing Guidelines
- There are currently no `*_test.go` files in the repo.
- New tests should live next to the package they cover and use standard Go naming (`foo_test.go`, `TestXxx`).
- No explicit coverage targets are defined; include tests for new behavior when feasible.

## Commit & Pull Request Guidelines
- This checkout has no Git history, so no commit convention is enforced yet. Use short, imperative subjects (e.g., “Add hashcat asset check”) and include context in the body when useful.
- PRs should describe behavior changes, list the commands run (e.g., `make`, `go test ./...`), and note asset updates if `go-assets.sh` was rerun.

## Security & Configuration Tips
- The build uses vendored dependencies (`-mod=vendor`), so keep `vendor/` in sync with `go.mod`/`go.sum` when updating deps.
- If you adjust Go version requirements, update both `go.mod` and the Makefile’s version validation logic.
