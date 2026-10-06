// Captured from a real holdfast 0.0.8 daemon (main c94ae82) under an isolated
// HOME, XDG and HOLDFAST_RUNTIME_DIR, through `claude -p` with this plugin
// loaded. Each is the text Claude Code hands on: `$.mcp.call` results carry
// `content[0].text` and no structuredContent, and next(e) for the tool call
// resolves to `{ result, text }`, both this text.

// `status` for a session sitting at `read -s -p '[sudo] password for deploy: '`.
export const STATUS_TEXT: string = "{\"data\":{\"args\":[],\"buffer\":{\"head\":624,\"resource_uri\":\"holdfast://session/sess_0f8fb4eb7af1/buffer\",\"tail\":0,\"total_bytes\":624},\"command\":\"bash\",\"command_capture\":\"captured\",\"command_count\":1,\"detection_tier\":\"terminal_mode\",\"exit_code\":null,\"exited_at_unix_secs\":null,\"id\":\"sess_0f8fb4eb7af1\",\"idle_deadline_unix_secs\":1791274916,\"interaction_mode\":\"AwaitingSecret\",\"last_activity_unix_ms\":1791273116885,\"name\":\"deploy\",\"osc133_source\":\"holdfast\",\"pid\":1981363,\"profile\":null,\"prompt\":{\"confidence\":0.95,\"cursor_score\":0.0,\"last_line\":\"[sudo] password for deploy: \",\"pattern_score\":0.95,\"quiescent_score\":1.0,\"reason\":\"echo disabled without leaving canonical mode, and no bracketed paste\"},\"redaction_stats\":{},\"screen_tracking\":\"off\",\"shell_integration\":\"bash\",\"started_at_unix_secs\":1791273116,\"state\":\"Running\",\"title\":null},\"details\":\"status of sess_0f8fb4eb7af1\",\"status\":\"ok\"}"

// request_secret_input answered in `holdfast attach` with `hunter2` and Enter.
export const PROVIDED_TEXT: string = "{\"data\":{\"bytes_written\":8,\"detection_tier\":\"semantic\",\"interaction_mode\":\"Executing\",\"prompt\":{\"confidence\":0,\"cursor_score\":0,\"last_line\":\"\",\"pattern_score\":0,\"quiescent_score\":0,\"reason\":\"osc 133 output marker with no completion since\"},\"request_id\":\"secreq_254ab843fbd1\",\"screen_tracking\":\"on\",\"title\":null},\"details\":\"8 byte(s) written to the session\",\"status\":\"secret_provided\"}"

// request_secret_input with timeout_secs 3 and nobody attached.
export const TIMEOUT_TEXT: string = "{\"data\":{\"reason\":\"timeout\",\"request_id\":\"secreq_0542e149996b\"},\"details\":\"the secret request ended: timeout\",\"status\":\"secret_cancelled\"}"

// request_secret_input once the read had finished and bash was back at its prompt.
export const AT_SHELL_PROMPT_TEXT: string = "{\"data\":{\"reason\":\"at_shell_prompt\"},\"details\":\"nothing was written: the session is at its shell prompt, where a secret would be shown, run as a command and saved to history. Run the command that asks for the secret first, and call this while it waits; if you have just started it, call wait_for_pattern with no pattern and call this again once interaction_mode is AwaitingSecret. If the command has already failed or ended, fix it and run it again\",\"status\":\"secret_cancelled\"}"
