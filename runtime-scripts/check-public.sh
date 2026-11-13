#!/usr/bin/env bash
# check-public.sh: run before every push.
#
#   bash runtime-scripts/check-public.sh             the server repo (works from anywhere inside it)
#   bash runtime-scripts/check-public.sh generator   another repo in a folder, checked with the same values
#
# Lists exactly what git would upload, then fails if any of it contains, in its text or in a
# file or folder name:
#   - a value from .env (the site names, the copyparty secret, ...)
#   - a WireGuard key or VPS address (read from the real, ignored wg*.conf files)
#   - this PC's user name or computer name
#   - secret-looking text, an email address, a public IP address or a Windows user folder
#   - a file that must never be uploaded, or one too big for GitHub
# It prints file names, line numbers and WHAT matched, never the matching value.
# Exit code: 0 = clean, 1 = something to fix, 2 = could not run.
set -uo pipefail

# Values in .env that are fine to appear in the repo:
PUBLIC_VARS="PUID PGID THREE_VERSION COMPOSE_FILE COMPOSE_PROJECT_NAME"

root=$(cd "$(dirname "$0")" && pwd)
while [ "$root" != "/" ] && [ ! -f "$root/docker-compose.yml" ]; do root=$(dirname "$root"); done
[ -f "$root/docker-compose.yml" ] || { echo "can't find the project folder (docker-compose.yml)"; exit 2; }
target=$(cd "${1:-$root}" 2>/dev/null && pwd) || { echo "no folder ${1:-}"; exit 2; }
cd "$target" || exit 2
command -v git >/dev/null || { echo "git is not installed"; exit 2; }
[ "$target" = "$root" ] || echo "checking $target with the values from $root"

umask 077
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

# ---- 1. What would be uploaded: tracked files plus new files that aren't ignored
if [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$target" ]; then
    git ls-files -z --cached --others --exclude-standard > "$tmp/all"
else
    git init -q "$tmp/idx"
    git --git-dir="$tmp/idx/.git" --work-tree=. ls-files -z --others --exclude-standard > "$tmp/all"
fi
# skip files that are tracked but already deleted on disk
while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done < "$tmp/all" > "$tmp/files"
count=$(tr -cd '\0' < "$tmp/files" | wc -c)

problems=0
say() { echo "  $*"; problems=$((problems + 1)); }
scan() { xargs -0 -r grep -IH "$@" < "$tmp/files" 2>/dev/null; }   # grep over every file to upload

# ---- 2. Files that must never be uploaded, and files too big for GitHub
echo "== files that must never be uploaded"
tr '\0' '\n' < "$tmp/files" \
  | grep -E '(^|/)(\.env|wg[0-9]*\.conf|users_database\.yml|users\.toml|JWT_SECRET|SESSION_SECRET|STORAGE_KEY|TEMP\.txt|NOTES\.txt)$|\.(db|sqlite|sqlite3|kdbx|p12|pfx|key|pem)$|^docs/' \
  | while IFS= read -r f; do echo "  $f"; done > "$tmp/out"
xargs -0 -r du -k < "$tmp/files" | awk -F'\t' '$1 > 51200 {printf "  %s is %d MB (GitHub warns over 50 MB and refuses over 100 MB)\n", $2, $1/1024}' >> "$tmp/out"
if [ -s "$tmp/out" ]; then cat "$tmp/out"; problems=$((problems + $(wc -l < "$tmp/out"))); fi

# ---- 3. Private values, read at run time (this script itself contains none)
: > "$tmp/private"          # lines: <i|s> <TAB> <what it is> <TAB> <value>   (i = ignore case)
declare -A seen
add() {   # add <i|s> <what> <value> <min length>; each value is checked once, under its first name
    local key="${3,,}"
    [ "${#3}" -ge "$4" ] && [ -z "${seen[$key]+x}" ] || return 0
    seen[$key]=1
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$tmp/private"
}
host_re='^([A-Za-z0-9-]+\.)*([A-Za-z0-9-]{5,})\.[A-Za-z]{2,}$'
if [ -f "$root/.env" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        [[ $line =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        name=${BASH_REMATCH[2]} val=${BASH_REMATCH[3]}
        case " $PUBLIC_VARS " in *" $name "*) continue ;; esac
        val=${val%\"}; val=${val#\"}; val=${val%\'}; val=${val#\'}
        add i "$name from .env" "$val" 6
        # the distinctive part of a site name ("example" in auth.example.com), or of a time zone
        if [[ $val =~ $host_re ]]; then add i "$name from .env (name part)" "${BASH_REMATCH[2]}" 5; fi
        if [[ $val == */* ]]; then add i "$name from .env (last part)" "${val##*/}" 5; fi
    done < "$root/.env"
else
    echo "(no .env here, so only the general checks run)"
fi
while IFS= read -r -d '' conf; do
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        if [[ $line =~ ^[[:space:]]*(PrivateKey|PublicKey|PresharedKey|Endpoint)[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
            field=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
            [ "$field" = Endpoint ] && val=${val%:*}
            add s "WireGuard $field from ${conf#"$root"/}" "$val" 6
        fi
    done < "$conf"
done < <(find "$root" \( -path "$root/internal-config" -o -path "$root/shared-files" -o -path "$root/logs" -o -path "$root/.git" \) -prune \
              -o -type f -name 'wg*.conf' -print0)
me=$(id -un 2>/dev/null || true); pc=$(hostname 2>/dev/null || true)
[ "$me" != root ] && add s "this PC's user name" "$me" 4
[ "$pc" != localhost ] && add s "this PC's name" "$pc" 4

echo "== private values (what matched: file:line)"
: > "$tmp/out"
while IFS=$'\t' read -r mode what val; do
    printf '%s\n' "$val" > "$tmp/pattern"
    flags=-nF; [ "$mode" = i ] && flags=-niF
    scan "$flags" -f "$tmp/pattern" | cut -d: -f1,2 | while IFS= read -r hit; do echo "  $what: $hit"; done >> "$tmp/out"
done < "$tmp/private"
rm -f "$tmp/pattern"
if [ -s "$tmp/out" ]; then sort -uV "$tmp/out"; problems=$((problems + $(sort -u "$tmp/out" | wc -l))); fi

echo "== private values in file or folder names (what matched: the path, with the match hidden)"
: > "$tmp/out"
tr '\0' '\n' < "$tmp/files" > "$tmp/paths"
while IFS=$'\t' read -r mode what val; do
    printf '%s\n' "$val" > "$tmp/pattern"
    awk -v what="$what" -v ci="$mode" '
        NR == FNR { v = $0; next }
        {
            t = (ci == "i") ? tolower(v) : v; s = (ci == "i") ? tolower($0) : $0
            i = index(s, t); if (!i) next
            j = index(substr($0, i + length(t)), "/")             # cut after the matching folder
            shown = (j > 0) ? substr($0, 1, i + length(t) + j - 2) : $0
            out = ""; ls = (ci == "i") ? tolower(shown) : shown
            while ((k = index(ls, t)) > 0) {
                out = out substr(shown, 1, k - 1) "***"
                shown = substr(shown, k + length(t)); ls = substr(ls, k + length(t))
            }
            print "  " what ": " out shown
        }' "$tmp/pattern" "$tmp/paths" >> "$tmp/out"
done < "$tmp/private"
rm -f "$tmp/pattern"
if [ -s "$tmp/out" ]; then sort -uV "$tmp/out"; problems=$((problems + $(sort -u "$tmp/out" | wc -l))); fi

# ---- 4. General patterns
echo "== secret-looking text, emails, public IPs, Windows user folders (what: file:line)"
: > "$tmp/out"
secret='x-idp-[0-9a-f]{16}|idp-h-key:[[:space:]]+[A-Za-z0-9_-]{6}|header_up[[:space:]]+[A-Za-z0-9_-]+[[:space:]]+1([[:space:]]|$)|(private|preshared)key[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=|\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{16}|gcdn_[A-Za-z0-9_-]{30}|BEGIN [A-Z ]*PRIVATE KEY'
scan -niE "$secret" | cut -d: -f1,2 | sed 's/^/  secret-looking text: /' >> "$tmp/out"
scan -nE '(^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=($|[^A-Za-z0-9+/=])' | cut -d: -f1,2 | sed 's/^/  key-shaped text: /' >> "$tmp/out"
scan -noE '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' \
  | grep -viE '@(example\.(com|org|net)|users\.noreply\.github\.com|github\.com)$' | cut -d: -f1,2 | sed 's/^/  email address: /' >> "$tmp/out"
scan -noE '\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b' | awk -F: '{
    ip = $NF; n = split(ip, o, "."); if (n != 4) next
    for (i = 1; i <= 4; i++) if (o[i] + 0 > 255) next
    a = o[1] + 0; b = o[2] + 0; c = o[3] + 0
    if (a == 0 || a == 10 || a == 127 || a >= 224) next                 # this host, private, loopback, multicast
    if ((a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)) next
    if (a == 100 && b >= 64 && b <= 127) next                             # carrier-grade NAT
    if ((a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113)) next  # documentation
    if (a == 198 && (b == 18 || b == 19)) next                            # benchmarking
    if (ip == "1.1.1.1" || ip == "1.0.0.1" || ip == "8.8.8.8" || ip == "8.8.4.4" || ip == "9.9.9.9") next   # public DNS
    print "  public IP address: " $1 ":" $2 }' >> "$tmp/out"
scan -niE '[A-Za-z]:\\Users\\|/mnt/[a-z]/Users/' | cut -d: -f1,2 | sed 's/^/  Windows user folder: /' >> "$tmp/out"
if [ -s "$tmp/out" ]; then sort -uV "$tmp/out"; problems=$((problems + $(sort -u "$tmp/out" | wc -l))); fi

echo
if [ "$problems" -eq 0 ]; then
    echo "clean: $count files would be uploaded, nothing private found"
    exit 0
fi
echo "NOT clean: $problems thing(s) above to fix before pushing ($count files checked)"
exit 1
