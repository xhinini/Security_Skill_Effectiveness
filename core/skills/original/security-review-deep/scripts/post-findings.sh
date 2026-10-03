#!/usr/bin/env bash
# Post security-review-deep findings as inline PR review comments.
#
# Reads the JSON sidecar the skill emits in --json mode (see SKILL.md
# Step 6) and turns each finding into a GitHub review comment via the
# REST review API. One review is posted per run; the review contains
# all findings above the severity threshold as a single batch so they
# render together on the PR.
#
# Requires:  gh (logged in), jq.
# Optional:  GITHUB_TOKEN env var if not using `gh auth`.
#
# Usage:
#   post-findings.sh [--findings FILE] [--pr N] [--repo OWNER/NAME]
#                    [--min-severity LEVEL] [--max-comments N]
#                    [--summary-only] [--dry-run]
#
# Defaults:
#   --findings        $WORKDIR/report.json or ./report.json
#   --pr              detected from `gh pr view --json number`
#   --repo            detected from `gh repo view --json nameWithOwner`
#   --min-severity    medium
#   --max-comments    50
#
# Exit codes:
#   0  posted (or dry-run printed) successfully
#   1  no findings at or above threshold (nothing to post)
#   2  usage / environment error

set -euo pipefail

FINDINGS="${WORKDIR:-.}/report.json"
[[ -f "$FINDINGS" ]] || FINDINGS="./report.json"
PR=""
REPO=""
MIN_SEVERITY="medium"
MAX_COMMENTS=50
SUMMARY_ONLY=0
DRY_RUN=0

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

while (( $# )); do
  case "$1" in
    --findings)      FINDINGS="$2"; shift 2 ;;
    --pr)            PR="$2"; shift 2 ;;
    --repo)          REPO="$2"; shift 2 ;;
    --min-severity)  MIN_SEVERITY="$2"; shift 2 ;;
    --max-comments)  MAX_COMMENTS="$2"; shift 2 ;;
    --summary-only)  SUMMARY_ONLY=1; shift ;;
    --dry-run)       DRY_RUN=1; shift ;;
    -h|--help)       usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

command -v gh >/dev/null 2>&1 || { echo "gh not on PATH; install GitHub CLI" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq not on PATH" >&2; exit 2; }

[[ -f "$FINDINGS" ]] || { echo "findings file not found: $FINDINGS" >&2; exit 2; }

# Resolve PR + repo if not passed.
if [[ -z "$REPO" ]]; then
  REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null) || {
    echo "could not detect repo; pass --repo OWNER/NAME" >&2; exit 2; }
fi
if [[ -z "$PR" ]]; then
  PR=$(gh pr view --json number -q .number 2>/dev/null) || {
    echo "could not detect PR; pass --pr N (or check out a PR branch)" >&2; exit 2; }
fi

# Severity rank for comparison. POSIX-portable lowercase (macOS bash 3.2
# doesn't support ${var,,}).
rank() {
  local lower
  lower=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$lower" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    *)        echo 0 ;;
  esac
}
MIN_RANK=$(rank "$MIN_SEVERITY")

# Build the comment array from the JSON sidecar. The sidecar's contract
# (per SKILL.md Step 6 / report-template.md) is a flat finding list with
# {file, line, rule, severity, composite, reachable, confidence, source,
#  suggested_fix, message}. Tolerate missing fields rather than failing.
WORK=$(mktemp -t post-findings.XXXXXX.json)
trap 'rm -f "$WORK"' EXIT

jq --argjson min_rank "$MIN_RANK" --argjson max "$MAX_COMMENTS" '
  def rank(s):
    if   (s|ascii_downcase) == "critical" then 4
    elif (s|ascii_downcase) == "high"     then 3
    elif (s|ascii_downcase) == "medium"   then 2
    elif (s|ascii_downcase) == "low"      then 1
    else 0 end;
  def emoji(s):
    if   (s|ascii_downcase) == "critical" then "⛔"
    elif (s|ascii_downcase) == "high"     then "⚠️"
    elif (s|ascii_downcase) == "medium"   then "🟡"
    elif (s|ascii_downcase) == "low"      then "🔵"
    else "•" end;
  def parse_loc(s):
    (s // "") as $s
    | ($s | capture("^(?<f>[^:]+):(?<l>[0-9]+)") // {f: $s, l: "0"})
    | {file: .f, line: (.l|tonumber)};
  [ .findings[]?
    | select(rank(.severity // "low") >= $min_rank)
    | parse_loc(.file) as $loc
    | {
        path:  $loc.file,
        line:  $loc.line,
        side:  "RIGHT",
        body:  (
          emoji(.severity // "low") + " **" + (.severity // "low" | ascii_upcase) + "** "
          + ((.rule // .category // "finding")) + "  \n"
          + (.message // .description // "")
          + (if .composite then "  \n_Composite: " + (.composite|tostring)
             + (if .reachable then ", reachable: " + .reachable else "" end)
             + (if .confidence then ", confidence: " + .confidence else "" end) + "_"
             else "" end)
          + (if .suggested_fix then "\n\n<details><summary>Suggested fix</summary>\n\n```\n"
             + .suggested_fix + "\n```\n\n</details>"
             else "" end)
          + (if .source then "  \n<sub>source: " + .source + "</sub>" else "" end)
        )
      }
  ]
  | sort_by(-(rank(.body | capture("\\*\\*(?<s>[A-Z]+)\\*\\*").s)))
  | .[0:$max]
' "$FINDINGS" > "$WORK"

COUNT=$(jq 'length' "$WORK")
if (( COUNT == 0 )); then
  echo "no findings at or above $MIN_SEVERITY in $FINDINGS"
  exit 1
fi

# Summary body. Pull banner counts from the sidecar if present.
SUMMARY=$(jq -r '
  if .summary then .summary
  else
    "Security review found "
    + (.findings | length | tostring)
    + " finding(s). KEV: "
    + ([.findings[]? | select(.kev == true)] | length | tostring)
    + " · EPSS>=0.5: "
    + ([.findings[]? | select((.epss // 0) >= 0.5)] | length | tostring)
    + " · Critical: "
    + ([.findings[]? | select((.severity // "") | ascii_downcase == "critical")] | length | tostring)
  end
' "$FINDINGS")

BODY=$(printf "## Security review (security-review-deep)\n\n%s\n\n<sub>Posted by post-findings.sh; threshold=%s; max=%d.</sub>" \
  "$SUMMARY" "$MIN_SEVERITY" "$MAX_COMMENTS")

if (( DRY_RUN )); then
  if (( SUMMARY_ONLY )); then
    echo "DRY RUN — would post a single summary review to $REPO PR #$PR (no inline comments)"
  else
    echo "DRY RUN — would post one review to $REPO PR #$PR with $COUNT comment(s)"
  fi
  echo "Summary:"
  printf "%s\n" "$BODY" | sed 's/^/  /'
  if (( ! SUMMARY_ONLY )); then
    echo
    echo "Comments:"
    jq -r '.[] | "  - " + .path + ":" + (.line|tostring) + "  " + (.body | split("\n") | .[0])' "$WORK"
  fi
  exit 0
fi

# Build the review payload and POST it as one batched review.
PAYLOAD=$(jq -n \
  --arg body "$BODY" \
  --slurpfile comments "$WORK" \
  '{event: "COMMENT", body: $body, comments: $comments[0]}')

if (( SUMMARY_ONLY )); then
  PAYLOAD=$(jq -n --arg body "$BODY" '{event: "COMMENT", body: $body}')
fi

echo "Posting review to $REPO PR #$PR ($COUNT comment(s) at >=$MIN_SEVERITY)..."
if echo "$PAYLOAD" | gh api -X POST "repos/$REPO/pulls/$PR/reviews" --input - >/dev/null; then
  echo "ok"
  exit 0
else
  echo "gh api POST failed" >&2
  exit 2
fi
