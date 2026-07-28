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

# Prove the report path is writable BEFORE running the scan. Otherwise bash
# fails to open the redirect, ward never executes at all, and $? is 1 - which
# maps to VERDICT=warn and exits 0. The step goes green having scanned
# nothing, which is the one outcome this action must never produce.
mkdir -p "$(dirname "${OUTPUT}")" 2>/dev/null || true
if ! : >"${OUTPUT}" 2>/dev/null; then
  echo "::error::Cannot write the Ward report to '${OUTPUT}'. Failing closed."
  exit 2
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

# EXIT 1 IS AMBIGUOUS AND IT IS THE DANGEROUS ONE. Ward returns 1 for a
# genuine WARN, and Python returns 1 for any uncaught exception - a broken
# install, a missing dependency, an interpreter crash mid-scan. Both landed
# on VERDICT=warn, which exits 0 and passes the job. So the single most
# likely way for this action to be broken produced a green tick.
#
# A real WARN leaves a report that SAYS so. A crash leaves an empty file, or
# a partial one, or a traceback. Requiring the report to corroborate the
# exit code is what separates them, and anything that does not corroborate
# fails closed.
if [[ "${VERDICT}" == "warn" ]]; then
  if [[ ! -s "${OUTPUT}" ]]; then
    echo "::error::Ward exited 1 and wrote no report - the scan did not complete. Failing closed."
    VERDICT="error"
  elif ! grep -qiE '"verdict"[[:space:]]*:[[:space:]]*"warn"|verdict:[[:space:]]*WARN' "${OUTPUT}"; then
    echo "::error::Ward exited 1 but its report does not record a WARN verdict - the scan did not complete. Failing closed."
    VERDICT="error"
  fi
fi

{
  echo "report=${OUTPUT}"
  echo "verdict=${VERDICT}"
} >>"${GITHUB_OUTPUT}"

echo "Ward verdict: ${VERDICT}"
echo "Report:       ${OUTPUT}"

# The whole report went to a file, so a failing run showed the maintainer a red
# tick and nothing else. Put the findings somewhere a human actually reads.
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Ward: ${VERDICT}"
    echo
    if [[ "${VERDICT}" == "pass" ]]; then
      echo "No injection patterns detected above the \`${THRESHOLD}\` threshold."
    else
      echo "Scanned \`${REPO}#${PR}\` with \`--fail-on ${FAIL_ON}\`."
      echo
      echo "<details><summary>Report (\`${OUTPUT}\`)</summary>"
      echo
      echo '```'
      # Cap it: a large SARIF document would blow the 1 MiB summary limit.
      head -c 60000 "${OUTPUT}" 2>/dev/null || echo "(report file unreadable)"
      echo
      echo '```'
      echo
      echo "</details>"
    fi
  } >>"${GITHUB_STEP_SUMMARY}" || true
fi

# Fail closed. An unexpected exit code means Ward did not run to completion
# (not installed, interpreter crash, killed), so the metadata was never
# actually screened. Passing the job here would turn a broken security gate
# into a green tick, which is the one outcome worse than a noisy failure.
if [[ "${VERDICT}" == "error" ]]; then
  echo "::error::Ward exited with code ${EXIT_CODE} without completing a scan. Failing closed."
  # Exit 1 would be indistinguishable from a plain FAIL to anything reading
  # this step's status, and an unexpected code could be 0. Always 2.
  exit 2
fi

if [[ "${VERDICT}" == "fail" ]]; then
  exit 1
fi
exit 0
