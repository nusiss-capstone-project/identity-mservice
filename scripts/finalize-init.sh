#!/usr/bin/env bash
# Post-init cleanup for repos created from the template.
set -euo pipefail

CANONICAL_TEMPLATE_REPO="${1:-lianjin/go-mservice-template}"
CURRENT_REPO="${2:-}"

if [ -z "${CURRENT_REPO}" ]; then
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then
    CURRENT_REPO="${GITHUB_REPOSITORY}"
  else
    echo "Usage: $0 [canonical_template_repo] <current_repo>"
    exit 1
  fi
fi

if [ "${CURRENT_REPO}" = "${CANONICAL_TEMPLATE_REPO}" ]; then
  echo "Canonical template repo; keep TEMPLATE.md and placeholder README."
  exit 0
fi

echo "Removing template-only files..."
rm -f TEMPLATE.md

if [ -f README.md ] && grep -q '__TEMPLATE_' README.md; then
  echo "README still contains placeholders; run replace-template-vars.sh first."
  exit 1
fi

echo "Finalize complete."
