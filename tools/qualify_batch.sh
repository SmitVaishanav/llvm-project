#!/bin/bash
# Batch-run AsyncSan qualifier on common Linux binaries.
# Usage: bash tools/qualify_batch.sh
# Requires: source ~/asyncsan-venv/bin/activate first

SCRIPT="$HOME/llvm-project/tools/asyncsan-qualify.py"

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
printf "%-30s %-12s %-8s %-8s %s\n" "BINARY" "VERDICT" "HANDLERS" "WRAPPERS" "WRAPPER NAMES"
printf "%-30s %-12s %-8s %-8s %s\n" "------" "-------" "--------" "--------" "-------------"

for bin in "${BINS[@]}"; do
    # Expand globs
    for resolved in $bin; do
        [ -f "$resolved" ] || continue
        name=$(basename "$resolved")

        # Run qualifier, capture stdout+stderr separately
        output=$(python3 "$SCRIPT" "$resolved" 2>/dev/null)
        rc=$?

        # Parse results from output
        handlers=$(echo "$output" | grep -oP 'Signal handlers found: \K\d+' || echo "0")
        wrappers=$(echo "$output" | grep -oP 'Auto-detected \K\d+' || echo "0")
        wrapper_names=$(echo "$output" | grep 'Auto-detected' | sed 's/.*function(s): //' || echo "")

        if echo "$output" | grep -q "FUZZ"; then
            verdict="FUZZ"
        elif echo "$output" | grep -q "INVESTIGATE"; then
            verdict="INVESTIGATE"
        elif [ "$handlers" != "0" ]; then
            verdict="SKIP-TRIV"
        else
            verdict="SKIP"
        fi

        printf "%-30s %-12s %-8s %-8s %s\n" \
            "$name" "$verdict" "$handlers" "$wrappers" "$wrapper_names"
    done
done

echo ""
echo "=============================================="
