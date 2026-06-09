"""Rule pattern registry — shared regex patterns for built-in rules."""

# ── Network patterns ───────────────────────────────────────────

URL_PATTERN = r"https?://[^\s\)\]\"']+"
CURL_WGET = r"\b(curl|wget)\s+"
DOWNLOAD_EXEC = r"\b(curl|wget).*\|.*\b(bash|sh|python|perl|ruby)"

# ── File system patterns ───────────────────────────────────────

SENSITIVE_FILES = (
    r"(~/.ssh/|~/.aws/|~/.gcloud/|~/.azure/|"
    r"\.env$|credentials|id_rsa|id_ed25519|"
    r"/etc/passwd|/etc/shadow)"
)

FULL_DISK_SCAN = r"\bos\.walk\(|glob\.glob\(\s*['\"]/\*\*|find\s+/\s+-type\s+f"

# ── Shell execution ────────────────────────────────────────────

SHELL_EXEC = (
    r"\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output)"
    r"|exec\s*\(|eval\s*\()"
)

REVERSE_SHELL = (
    r"\b(socket\.(socket|connect)|pty\.spawn|"
    r"nc\s+.*-e\s+/bin/(bash|sh)|bash\s+-i\s+>&)"
)

# ── Credential patterns ────────────────────────────────────────

ENV_CREDENTIALS = (
    r"\b(AWS_ACCESS_KEY|AWS_SECRET|AZURE_SUBSCRIPTION|"
    r"GCP_SERVICE_ACCOUNT|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"DATABASE_URL|REDIS_URL|STRIPE_KEY|GITHUB_TOKEN)"
)

CREDENTIAL_STEAL = r"\bos\.(environ|getenv)\s*\(\s*['\"](?!HOME|USER|PATH|LANG|SHELL)"

# ── Persistence patterns ───────────────────────────────────────

PERSISTENCE = r"\b(crontab|bashrc|\.profile|systemd|launchd|autorun|startup)"

# ── Prompt injection patterns ──────────────────────────────────

ROLE_HIJACK = (
    r"\b(act as|you are now|pretend|roleplay|"
    r"persona|you are a|new identity|character)"
)

SAFETY_BYPASS = (
    r"\b(no restriction|bypass|developer mode|jailbreak|"
    r"ignore.*safety|unrestrict|do anything|no rules)"
)

INSTRUCTION_OVERRIDE = (
    r"\b(ignore.*(previous|above|prior).*instruction|"
    r"forget.*(everything|what|instruction)|"
    r"disregard.*(previous|rule|guideline)|"
    r"override.*(system|prompt|instruction))"
)

SYSTEM_PROMPT_LEAK = (
    r"\b(system prompt|reveal.*(instruction|prompt)|"
    r"show.*(prompt|instruction|setting)|"
    r"what were you told|repeat.*(instruction|rule)|"
    r"print.*your.*(instruction|prompt|rule))"
)
