# CLASP — Claude's Live Agent Shell Proxy

An MCP server that gives AI agents (Claude Code, etc.) full interactive shell access via persistent PTY-backed sessions.

## Project Status

**Phase: Brainstorming / Design** — No code written yet. Working through the brainstorming process to produce a production-quality design spec before any implementation begins.

## Key Decision Log

- **Project name:** CLASP (Claude's Live Agent Shell Proxy)
- **Approach:** MCP server (not a CLI tool like shellwright) — tighter integration with Claude Code via native MCP tools
- **Goal:** Production quality, comprehensive testing, adversarial review
- **Cost/effort:** Not a constraint — thoroughness is prioritized

## What This Project Is

A standalone MCP server that:
- Spawns interactive programs inside real PTYs
- Exposes MCP tools for session lifecycle (start, send input, read output, wait for patterns, terminate)
- Handles password prompts, sudo, SSH, interactive installers, REPLs, and any command that needs stdin
- Designed to be used from Claude Code (and potentially other AI agents)

## Prior Art

- **shellwright** (https://github.com/nielsbosma/shellwright) — Rust CLI daemon that solves the same problem but as a CLI tool, not an MCP server. Good reference for prompt detection, token-efficient output reading, and security features.
