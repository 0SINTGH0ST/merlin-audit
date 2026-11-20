# merlin-audit

Read-only security auditor for ASUS Merlin routers.

- CVE scan (NVD + CISA KEV)
- Open port check
- Config / Wi-Fi / DNS audit
- ASUS backdoor IOC detection
- Baseline integrity diff
- `--json` output (feeds Cerberus Firewall)

## Install

```sh
curl -sL https://raw.githubusercontent.com/0SINTGH0ST/merlin-audit/main/merlin-audit.sh -o /jffs/scripts/merlin-audit.sh
chmod +x /jffs/scripts/merlin-audit.sh
/jffs/scripts/merlin-audit.sh
```

Read-only: makes no changes to the router.
