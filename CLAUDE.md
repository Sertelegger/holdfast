# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CLASP** (Claude's Live Agent Shell Proxy) — An MCP server that gives AI agents a persistent, PTY-backed shell environment. Solves the problem that Claude Code's Bash tool runs non-interactive, isolated processes with no PTY, no stdin, and no session persistence.

**Framing:** CLASP gives the agent a persistent shell environment, the way tmux gives a developer one.

## Project Status

**Phase: Design complete, awaiting user review of spec → implementation planning.**

The full design specification is at `docs/superpowers/specs/2026-05-01-clasp-design.md`. Read it for any non-trivial work in this repo. The historical brainstorming notes are at `docs/brainstorming-progress.md` (kept as a record; superseded by the spec).

## Stack and Architecture (decided)

- **Language:** Rust
- **Architecture:** Single Cargo workspace with `clasp-core` (library) + `clasp` (single binary with subcommands: `mcp`, `daemon`, `attach`, `watch`, `list`, `logs`, `ui`, ...)
- **Transport:** Hybrid mode on Linux/macOS/WSL — stdio MCP shim + persistent Unix-socket daemon. Stdio-only mode on Windows native (sessions die with the shim).
- **PTY:** `portable-pty` crate via a `PtyBackend` trait. v0.1.0 ships `InProcessPty`; `SubprocessPty` (process-isolated) is the priority post-v0.1.0 feature.
- **MCP SDK:** `rmcp` (Rust)
- **Distribution:** GitHub Releases (prebuilt per-platform binaries) + `cargo install` + Claude Code plugin marketplace (this repo doubles as marketplace; bootstrap launcher fetches binaries on demand).

## v0.1.0 Scope

11 MCP tools — `precheck_command`, `start_session` (with two-phase preflight), `send_input`, `request_secret_input`, `read_output`, `wait_for_pattern`, `resize`, `interrupt`, `terminate`, `list_sessions`, `status`. Tool annotations per MCP 2025-06-18 spec (`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`). Full hybrid mode on Linux/macOS/WSL, stdio-only on Windows. CLI subcommands: `clasp attach`/`watch`/`list`/`logs` (with `--raw`)/`ui`/`confirm`. Web UI with `xterm.js` (Unix-socket-only daemon; TCP bridge via `clasp ui` with bearer-token + Origin/Host validation). Gitleaks-derived secret redaction at every output boundary including audit logs. Argv-aware dangerous-command preflight with optional code-based `strict_confirmation` mode (agent gets token, only trusted UI sees the code). `request_secret_input` for out-of-band secret entry via attached clients (CLI attach `SecretInput` frame, web UI masked input). Process-group signal semantics (`setsid` Unix / job objects Windows). Multi-signal prompt detection with new combiner (`confidence = quiescent_score * pattern_score`). Bounded `read_output` responses (raw-byte budget; bulk output as MCP resources). Comprehensive testing across unit / integration / cross-platform CI / adversarial tiers.

See spec §12.6 for the full ship-list and §14 for the post-v0.1.0 roadmap.
