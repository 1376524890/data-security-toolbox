rule SensitiveCredential
{
    meta:
        description = "Detects common credential and API key patterns"
        severity = "critical"
    strings:
        $password = /\b(password|passwd|pwd)\b[ \t]*[=:][ \t]*[!-~]{8,120}[ \t]*\r?\n/i ascii
        $secret = /\b(secret|api[_-]?key|access[_-]?key|private[_-]?key)\b[ \t]*[=:][ \t]*[!-~]{8,120}[ \t]*\r?\n/i ascii
        $provider = /(akia|ghp_|sk-|aiza)[a-z0-9_-]{16,}/i ascii
    condition:
        filesize < 20MB and any of them
}
