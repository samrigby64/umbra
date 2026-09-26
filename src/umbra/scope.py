"""Exact hostname scope, shared by discovery, queue claims and redirect hooks."""
from urllib.parse import urlsplit


class ScopeError(ValueError):
    pass


def valid_host(url: str) -> str:
    try:
        if any(c.isspace() or ord(c) < 32 for c in url):
            raise ValueError("Whitespace is not allowed in URLs")
        parsed = urlsplit(url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or len(url) > 2048):
            raise ValueError("invalid HTTP URL")
        _ = parsed.port
        return parsed.hostname.rstrip(".").encode("idna").decode().lower()
    except (ValueError, UnicodeError) as exc:
        raise ScopeError(f"Invalid crawl URL: {url[:100]}") from exc


def canonical_hosts(hosts: list[str]) -> list[str]:
    result = []
    for host in hosts:
        value = host.strip()
        if not value or any(c in value for c in "/?#@"):
            raise ScopeError("Allowed hosts must be hostnames, without paths or credentials")
        result.append(valid_host("http://" + value))
    return sorted(set(result))


def allows(url: str, hosts: list[str]) -> bool:
    host = valid_host(url)
    return not hosts or host in hosts
