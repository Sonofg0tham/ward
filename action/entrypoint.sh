#!/usr/bin/env bash
# Composite-action entrypoint for Ward.
#
# Resolves the PR number from inputs or the event payload, builds the
# ward command line, and writes the report to a file. The verdict is
# exposed as a step output so workflows can react without re-parsing the
# report.

set -euo pipefail

PR="${WARD_PR_INPUT:-}"
REPO="${WARD_REPO_INPUT:-${GITHUB_REPOSITORY:-}}"
FAIL_ON="${WARD_FAIL_ON:-high}"
THRESHOLD="${WARD_THRESHOLD:-low}"
FORMAT="${WARD_FORMAT:-sarif}"
OUTPUT="${WARD_OUTPUT:-}"
RULE_PACK="${WARD_RULE_PACK:-}"

if [[ -z "${PR}" && -n "${GITHUB_EVENT_PATH:-}" && -r "${GITHUB_EVENT_PATH}" ]]; then
  PR="$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH}")"
fi

if [[ -z "${PR}" ]]; then
  echo "::error::No PR number supplied and no pull_request.number in the event payload."
  exit 2
fi

if [[ -z "${REPO}" ]]; then
  echo "::error::No repository supplied. Set the 'repository' input or run inside a GitHub workflow."
  exit 2
fi

if [[ -z "${OUTPUT}" ]]; then
  case "${FORMAT}" in
    sarif) OUTPUT="ward-report.sarif" ;;
    json)  OUTPUT="ward-report.json"  ;;
    *)     OUTPUT="ward-report.txt"   ;;
  esac
fi

cmd=(ward scan-pr "${REPO}#${PR}"
     --format "${FORMAT}"
     --severity-threshold "${THRESHOLD}"
     --fail-on "${FAIL_ON}")

if [[ -n "${RULE_PACK}" ]]; then
  cmd+=(--rule-pack "${RULE_PACK}")
fi

# Capture stdout but preserve the exit code (pipefail handles upstream).
set +e
"${cmd[@]}" >"${OUTPUT}"
EXIT_CODE=$?
set -e

case "${EXIT_CODE}" in
  0) VERDICT="pass" ;;
  1) VERDICT="warn" ;;
  2) VERDICT="fail" ;;
  *) VERDICT="error" ;;
esac

{
  echo "report=${OUTPUT}"
  echo "verdict=${VERDICT}"
} >>"${GITHUB_OUTPUT}"

echo "Ward verdict: ${VERDICT}"
echo "Report:       ${OUTPUT}"

if [[ "${VERDICT}" == "fail" ]]; then
  exit 1
fi
exit 0
