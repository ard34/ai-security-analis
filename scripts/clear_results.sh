#!/usr/bin/env bash
set -euo pipefail

WITH_TMP=false
WITH_LOGS=false
BACKUP=false

for arg in "$@"; do
  case "$arg" in
    --with-tmp) WITH_TMP=true ;;
    --with-logs) WITH_LOGS=true ;;
    --backup) BACKUP=true ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

python - <<PY
from agent.core.result_manager import clear_previous_results
result = clear_previous_results(clear_tmp=${WITH_TMP}, clear_logs=${WITH_LOGS}, backup=${BACKUP})
print(result)
PY
