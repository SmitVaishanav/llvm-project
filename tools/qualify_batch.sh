#!/bin/bash
# Batch-run AsyncSan qualifier on common Linux binaries.
# Usage: bash tools/qualify_batch.sh
# Requires: source ~/asyncsan-venv/bin/activate first

QUALIFY="python3 ~/llvm-project/tools/asyncsan-qualify.py"

# Common signal-using binaries
BINS=(
    /usr/sbin/sshd
    /usr/bin/bash
    /usr/bin/dash
    /usr/bin/screen
    /usr/bin/tmux
    /usr/bin/curl
    /usr/bin/wget
    /usr/bin/git
    /usr/bin/vim
    /usr/bin/nano
    /usr/bin/top
    /usr/bin/htop
    /usr/bin/ssh
    /usr/bin/scp
    /usr/bin/rsync
    /usr/bin/make
    /usr/bin/python3
    /usr/sbin/nginx
    /usr/sbin/apache2
    /usr/bin/redis-server
    /usr/bin/redis-cli
    /usr/lib/postgresql/*/bin/postgres
    /usr/bin/mysqld
    /usr/bin/mongod
)

echo "=============================================="
echo " AsyncSan Binary Qualification — Batch Report"
echo "=============================================="
echo ""
printf "%-30s %-10s %-8s %-8s %s\n" "BINARY" "VERDICT" "HANDLERS" "WRAPPERS" "NOTES"
printf "%-30s %-10s %-8s %-8s %s\n" "------" "-------" "--------" "--------" "-----"

for bin in "${BINS[@]}"; do
    # Expand globs
    for resolved in $bin; do
        [ -f "$resolved" ] || continue
        name=$(basename "$resolved")

        # Run qualifier, capture output
        output=$($QUALIFY "$resolved" 2>/dev/null)

        # Parse results
        verdict=$(echo "$output" | grep "VERDICT:" | sed 's/.*VERDICT: //')
        handlers=$(echo "$output" | grep "Signal handlers found:" | grep -oP '\d+')
        wrappers=$(echo "$output" | grep "Auto-detected" | grep -oP '\d+')
        wrapper_names=$(echo "$output" | grep "Auto-detected" | sed 's/.*function(s): //')

        [ -z "$handlers" ] && handlers="0"
        [ -z "$wrappers" ] && wrappers="0"
        [ -z "$verdict" ] && verdict="SKIP (no handlers)"

        printf "%-30s %-10s %-8s %-8s %s\n" \
            "$name" "${verdict%%(*}" "$handlers" "$wrappers" "$wrapper_names"
    done
done

echo ""
echo "=============================================="
