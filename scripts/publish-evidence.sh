#!/usr/bin/env bash
# Usage: publish-evidence.sh <run-dir> <run-id>
# Appends a run's evidence to the orphan "evidence" branch and updates latest/.
set -euo pipefail

run_dir=$(realpath "$1")
run_id=$2

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

if git fetch --depth=1 origin evidence 2>/dev/null; then
  git switch --quiet -C evidence FETCH_HEAD
else
  git switch --quiet --orphan evidence
fi

rm -rf "runs/$run_id" latest
mkdir -p "runs/$run_id" latest
cp -r "$run_dir/." "runs/$run_id/"
cp "$run_dir/audit.jsonl" "$run_dir/run.json" latest/
printf '%s\n' "$run_id" > latest/RUN_ID

git add --all runs latest
if git diff --cached --quiet; then
  echo "Evidence for $run_id is unchanged."
  exit 0
fi
git commit --quiet -m "Evidence for run $run_id"
git push --quiet origin evidence
