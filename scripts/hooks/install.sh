#!/usr/bin/env bash
# Symlink tracked hooks into .git/hooks/
set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/scripts/hooks"

for hook in "$HOOKS_DIR"/*; do
    name="$(basename "$hook")"
    [ "$name" = "install.sh" ] && continue
    ln -sf "$hook" "$REPO_ROOT/.git/hooks/$name"
    echo "Installed $name"
done
