// Synthetic sample data. Entirely fictional (acme.io is not a real target).
// Never replace with real scanner output or any system you are not authorized to scan.

export const SAMPLE_FINDINGS = `[nuclei] [high] CVE-2021-44228 Log4j RCE — matched at https://api.prod.acme.io/login
[nuclei] [high] CVE-2021-44228 Log4j RCE — matched at https://api.prod.acme.io/login (header X-Api-Version)
[nuclei] [critical] exposed-.git-config — matched at https://shop.prod.acme.io/.git/config
[nuclei] [medium] tls-version-1.0-detected — matched at https://mail.prod.acme.io:443
[nuclei] [low] missing-x-frame-options — matched at https://blog.acme.io
[nuclei] [low] missing-x-frame-options — matched at https://blog.acme.io/about
[nuclei] [low] missing-x-frame-options — matched at https://blog.acme.io/contact
[nuclei] [info] http-missing-security-headers — matched at https://blog.acme.io
[burp] [high] SQL injection (boolean-based) — https://shop.prod.acme.io/search?q=
[burp] [medium] Reflected XSS — https://shop.prod.acme.io/search?q=
[burp] [medium] Reflected XSS — https://shop.prod.acme.io/search?ref=
[nuclei] [critical] default-credentials Jenkins — matched at https://ci.internal.acme.io:8080
[nuclei] [high] CVE-2023-23397 Outlook — matched at https://mail.prod.acme.io
[nuclei] [medium] cors-misconfig-wildcard — matched at https://api.prod.acme.io
[nuclei] [low] cookie-without-secure-flag — matched at https://staging.acme.io
[nuclei] [info] tech-detect: nginx 1.18 — matched at https://blog.acme.io
[nessus] [medium] SSL Certificate expires in 12 days — mail.prod.acme.io
[nuclei] [high] CVE-2014-0160 Heartbleed — matched at https://legacy-vpn.acme.io
[burp] [low] verbose-error-message — https://staging.acme.io/api/debug
[nuclei] [medium] open-redirect — matched at https://shop.prod.acme.io/out?url=`;

export const SAMPLE_CONTEXT = `prod.acme.io hosts are internet-facing and process customer payment data.
ci.internal.acme.io is internal-only but holds source code and deploy keys.
staging.acme.io and legacy-vpn.acme.io are internet-facing; legacy-vpn is slated for decommission.
blog.acme.io is a static marketing site with no sensitive data.`;
