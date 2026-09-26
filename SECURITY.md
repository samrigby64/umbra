# Security

Please report vulnerabilities privately through GitHub's **Report a
vulnerability** button on this repository's Security tab, rather than in a
public issue. Include the version, how to reproduce it, and the impact you expect.

This is a personal portfolio project, not a supported product. There is no
service-level commitment, but reports are read and fixed where possible.

In scope: the API, authentication and sessions, the SSRF guard (webhooks and
non-Tor fetches), evidence export and the standalone verifier, backup
encryption, and handling of hostile page content.

Out of scope: the security of the sites a deployment chooses to crawl, and
deployments that ignore the documented requirements (TLS and authenticated
infrastructure for remote access).
