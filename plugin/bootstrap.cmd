@echo off
rem Holdfast plugin bootstrap, Windows shim. Reached only if the plugin
rem loader's spawn resolves the extensionless `${CLAUDE_PLUGIN_ROOT}/bootstrap`
rem through PATHEXT -- see the header comment in `bootstrap` for why the
rem manifest cannot name a per-platform command and why this is the shape
rem that lets one string be both. UNVERIFIED on a real Windows host.
rem
rem Nothing here may write to stdout: stdout is the MCP JSON-RPC transport.
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%~dp0bootstrap.ps1" %*
exit /b %ERRORLEVEL%
