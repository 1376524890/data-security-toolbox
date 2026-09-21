rule SensitiveCredential
{
    meta:
        description = "Detects common credential and API key patterns"
        severity = "critical"
    strings:
        $password = /password\s*[=:]\s*[^\s]+/i
        $secret = /secret\s*[=:]\s*[^\s]+/i
        $api = /(akia|ghp_|sk-|aiza)[a-z0-9_-]{16,}/i
    condition:
        any of them
}

