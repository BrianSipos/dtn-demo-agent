#!/bin/bash
# Format the source and check for any local changes
set -e

# Python source and test fixtures
autopep8 -ir .


changed=$(git status --porcelain=1)
if [ -n "${changed}" ]; then
  echo "Error: Files changed after formatting:"
  git diff
  exit 1
fi
