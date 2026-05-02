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

8 MCP tools (`start_session`, `send_input`, `read_output`, `wait_for_pattern`, `interrupt`, `terminate`, `list_sessions`, `status`), full hybrid mode on Unix, stdio-only on Windows, `clasp attach`/`watch`/`list`/`logs`/`ui` CLI subcommands, web UI with `xterm.js` (served over Unix socket; TCP bridge via `clasp ui` only), gitleaks-derived secret redaction with AI-provider augmentations, multi-signal prompt detection, comprehensive testing across unit / integration / cross-platform CI / adversarial tiers.

See spec §12.6 for the full ship-list and §14 for the post-v0.1.0 roadmap.
