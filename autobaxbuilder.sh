#!/bin/bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
N_SCENARIOS=1          # total number of scenarios to generate
N_PARALLEL=1           # number of concurrent workers
DIFFICULTY=3           # difficulty level (1=easy, 3=medium, 5=hard)
DEBUG=0                # debug mode for python calls (0=off, 1=on)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_PATH="$SCRIPT_DIR/artifacts"   # base directory for all generated output

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
R='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[38;5;45m'
ORANGE='\033[38;2;236;150;59m'
GREEN='\033[38;5;83m'
RED='\033[38;5;203m'
YELLOW='\033[38;5;221m'
WHITE='\033[97m'
GRAY='\033[38;5;245m'

# ─────────────────────────────────────────────────────────────────────────────
# WELCOME SCREEN
# ─────────────────────────────────────────────────────────────────────────────
print_welcome() {
    echo ""
    echo -e "  ${BOLD}${ORANGE}AutoBaxBuilder${R}"
    echo -e "  ${DIM}Bootstrapping Code Security Benchmarking${R}"
    echo ""
    echo -e "  ${GRAY}arxiv.org/abs/2512.21132  ·  github.com/eth-sri/autobaxbuilder  ·  baxbench.com/autobaxbuilder${R}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${R} $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --n-scenarios N    Total scenarios to generate          (default: $N_SCENARIOS)"
    echo "  -P, --parallel N       Parallel workers                     (default: $N_PARALLEL)"
    echo "  -d, --difficulty N     Difficulty: 1=easy 3=medium 5=hard   (default: $DIFFICULTY)"
    echo "  -p, --path PATH        Artifacts base directory             (default: <script_dir>/artifacts)"
    echo "  -v, --debug            Enable debug output in python calls  (default: off)"
    echo "  -h, --help             Show this help"
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# ARG PARSING
# ─────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--n-scenarios) N_SCENARIOS="$2"; shift 2 ;;
        -P|--parallel)    N_PARALLEL="$2";  shift 2 ;;
        -d|--difficulty)  DIFFICULTY="$2";  shift 2 ;;
        -p|--path)        ARTIFACT_PATH="$2"; shift 2 ;;
        -v|--debug)       DEBUG=1; shift ;;
        -h|--help)        usage ;;
        *) echo -e "${RED}Unknown option: $1${R}"; usage ;;
    esac
done

print_welcome

# ─────────────────────────────────────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────────────────────────────────────
export $(grep -v '^#' .env | xargs)
export ARTIFACT_PATH
export DIFFICULTY
export DEBUG

DEBUG_FLAG=""
[ "$DEBUG" = "1" ] && DEBUG_FLAG="--debug"
export DEBUG_FLAG

mkdir -p "$ARTIFACT_PATH"
find "$ARTIFACT_PATH" -maxdepth 1 -type f -name 'token_usage_*' -delete

STATUS_DIR=$(mktemp -d)
export STATUS_DIR

trap 'rm -rf "$STATUS_DIR"' EXIT

case "$DIFFICULTY" in
    1) DIFF_LABEL="easy   (1 endpoint)" ;;
    3) DIFF_LABEL="medium (3 endpoints)" ;;
    5) DIFF_LABEL="hard   (5 endpoints)" ;;
    *) DIFF_LABEL="custom ($DIFFICULTY endpoints)" ;;
esac

echo -e "  ${BOLD}Configuration${R}"
echo -e "  ${GRAY}─────────────────────────────────────────${R}"
echo -e "  ${GRAY}Scenarios  ${R}  ${WHITE}$N_SCENARIOS${R}"
echo -e "  ${GRAY}Parallel   ${R}  ${WHITE}$N_PARALLEL${R}"
echo -e "  ${GRAY}Difficulty ${R}  ${WHITE}$DIFF_LABEL${R}"
echo -e "  ${GRAY}Debug      ${R}  ${WHITE}$([ "$DEBUG" = "1" ] && echo on || echo off)${R}"
echo -e "  ${GRAY}Artifacts  ${R}  ${WHITE}$ARTIFACT_PATH${R}"
echo -e "  ${GRAY}─────────────────────────────────────────${R}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# WORKER FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
run_scenario() {
    set -euo pipefail

    IDX=$1
    LOGFILE=$(mktemp)
    START_TIME=$(date +%s)

    echo "[Worker $IDX] Starting scenario generation..."

    # shellcheck disable=SC2086
    if ! python src/main.py $DEBUG_FLAG --path "$ARTIFACT_PATH" --difficulty "$DIFFICULTY" --generate_scenarios 2>&1 | tee "$LOGFILE"; then
        END_TIME=$(date +%s)
        ELAPSED=$(( END_TIME - START_TIME ))
        echo "FAIL|$IDX|generate_scenario failed|${ELAPSED}s" > "$STATUS_DIR/$IDX.result"
        rm -f "$LOGFILE"
        return 1
    fi

    LAST_LINE=$(tail -n 1 "$LOGFILE")
    ESCAPED_ARTIFACT_PATH=$(printf '%s\n' "$ARTIFACT_PATH" | sed 's/[\/&]/\\&/g')
    SCENARIO_NAME=$(sed -nE "s/.*Saved scenario to ${ESCAPED_ARTIFACT_PATH}\/([^/]+)\/[^/]+\.json.*/\1/p" "$LOGFILE" | tail -n1)

    if [ -z "$SCENARIO_NAME" ]; then
        END_TIME=$(date +%s)
        ELAPSED=$(( END_TIME - START_TIME ))
        echo "FAIL|$IDX|could not extract scenario name from: $LAST_LINE|${ELAPSED}s" > "$STATUS_DIR/$IDX.result"
        rm -f "$LOGFILE"
        return 1
    fi

    echo "[Worker $IDX] Extracted scenario name: $SCENARIO_NAME"

    # shellcheck disable=SC2086
    if ! python src/main.py $DEBUG_FLAG --path "$ARTIFACT_PATH" --difficulty "$DIFFICULTY" --generate_tests --scenario "$SCENARIO_NAME" 2>&1 | tee -a "$LOGFILE"; then
        END_TIME=$(date +%s)
        ELAPSED=$(( END_TIME - START_TIME ))
        echo "FAIL|$IDX|generate_tests failed for $SCENARIO_NAME|${ELAPSED}s" > "$STATUS_DIR/$IDX.result"
        SCENARIO_DIR="$ARTIFACT_PATH/$SCENARIO_NAME"
        mv "$LOGFILE" "$SCENARIO_DIR/agent.log" 2>/dev/null || rm -f "$LOGFILE"
        return 1
    fi

    # shellcheck disable=SC2086
    if ! python src/main.py $DEBUG_FLAG --path "$ARTIFACT_PATH" --difficulty "$DIFFICULTY" --generate_exploits --scenario "$SCENARIO_NAME" 2>&1 | tee -a "$LOGFILE"; then
        END_TIME=$(date +%s)
        ELAPSED=$(( END_TIME - START_TIME ))
        echo "FAIL|$IDX|generate_exploits failed for $SCENARIO_NAME|${ELAPSED}s" > "$STATUS_DIR/$IDX.result"
        SCENARIO_DIR="$ARTIFACT_PATH/$SCENARIO_NAME"
        mv "$LOGFILE" "$SCENARIO_DIR/agent.log" 2>/dev/null || rm -f "$LOGFILE"
        return 1
    fi

    SCENARIO_DIR="$ARTIFACT_PATH/$SCENARIO_NAME"
    mv "$LOGFILE" "$SCENARIO_DIR/agent.log"

    # Copy the version-sort latest .py file out of the scenario dir as <SCENARIO>.py
    LATEST_PY=$(ls "$SCENARIO_DIR"/*.py 2>/dev/null | xargs -n1 basename | sort -V | tail -n1 || true)

    OUTPUT_FILE=""
    if [ -n "$LATEST_PY" ]; then
        OUTPUT_FILE="$ARTIFACT_PATH/${SCENARIO_NAME}.py"
        cp "$SCENARIO_DIR/$LATEST_PY" "$OUTPUT_FILE"
        echo "[Worker $IDX] Copied '$LATEST_PY' -> ${SCENARIO_NAME}.py"
    else
        echo "[Worker $IDX] Warning: no Python files found in $SCENARIO_DIR"
    fi

    END_TIME=$(date +%s)
    ELAPSED=$(( END_TIME - START_TIME ))
    echo "OK|$IDX|$SCENARIO_NAME|$OUTPUT_FILE|${ELAPSED}s" > "$STATUS_DIR/$IDX.result"
    echo "[Worker $IDX] Done: $SCENARIO_NAME (${ELAPSED}s)"
}

export -f run_scenario

# ─────────────────────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────────────────────
echo -e "  ${BOLD}Running${R}  ${GRAY}(${N_SCENARIOS} scenarios, ${N_PARALLEL} parallel)${R}"
echo ""

GLOBAL_START=$(date +%s)

set +e
seq 1 "$N_SCENARIOS" | xargs -n1 -P"$N_PARALLEL" bash -c 'run_scenario "$@"' _
set -e

GLOBAL_END=$(date +%s)
GLOBAL_ELAPSED=$(( GLOBAL_END - GLOBAL_START ))

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${ORANGE}┌───────────┐${R}"
echo -e "  ${ORANGE}│${R}  ${BOLD}${WHITE}SUMMARY${R}  ${ORANGE}│${R}"
echo -e "  ${ORANGE}└───────────┘${R}"
echo ""

N_OK=0
N_FAIL=0
FAIL_LINES=()
OK_LINES=()

for f in "$STATUS_DIR"/*.result; do
    [ -f "$f" ] || continue
    line=$(cat "$f")
    status=$(echo "$line" | cut -d'|' -f1)
    if [ "$status" = "OK" ]; then
        scenario=$(echo "$line" | cut -d'|' -f3)
        outfile=$(echo "$line" | cut -d'|' -f4)
        elapsed=$(echo "$line" | cut -d'|' -f5)
        out_display="${outfile##*/}"
        [ -z "$out_display" ] && out_display="(no .py file found)"
        OK_LINES+=("  ${GREEN}✓${R}  ${WHITE}${scenario}${R}  ${GRAY}→  ${out_display}  ${DIM}[${elapsed}]${R}")
        N_OK=$(( N_OK + 1 ))
    else
        worker=$(echo "$line" | cut -d'|' -f2)
        reason=$(echo "$line" | cut -d'|' -f3)
        elapsed=$(echo "$line" | cut -d'|' -f4)
        FAIL_LINES+=("  ${RED}✗${R}  ${GRAY}worker ${worker}${R}  ${RED}${reason}${R}  ${DIM}[${elapsed}]${R}")
        N_FAIL=$(( N_FAIL + 1 ))
    fi
done

for l in "${OK_LINES[@]+"${OK_LINES[@]}"}"; do echo -e "$l"; done
for l in "${FAIL_LINES[@]+"${FAIL_LINES[@]}"}"; do echo -e "$l"; done

echo ""
echo -e "  ${GRAY}─────────────────────────────────────────────────────────────${R}"

if [ "$N_FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All ${N_OK} scenarios completed successfully${R}  ${GRAY}(total: ${GLOBAL_ELAPSED}s)${R}"
elif [ "$N_OK" -eq 0 ]; then
    echo -e "  ${RED}${BOLD}All ${N_FAIL} scenarios failed${R}  ${GRAY}(total: ${GLOBAL_ELAPSED}s)${R}"
else
    echo -e "  ${YELLOW}${BOLD}${N_OK} succeeded${R}  ${GRAY}·${R}  ${RED}${BOLD}${N_FAIL} failed${R}  ${GRAY}(total: ${GLOBAL_ELAPSED}s)${R}"
fi

echo ""
