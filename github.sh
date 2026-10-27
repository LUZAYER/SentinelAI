#!/bin/bash

set -e

read -rp "Enter commit message: " message

if [[ -z "$message" ]]; then
    echo "Error: Commit message cannot be empty."
    exit 1
fi

git add .

if ! git diff --cached --quiet; then
    git commit -m "$message"
else
    echo "No staged changes to commit."
fi

git push -u origin HEAD
