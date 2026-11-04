#!/bin/sh
# Shared quality checks for the pre-commit hook and CI:
# formatting, vet, lint, tests and documentation pairs (EN/DE).
# Usage: scripts/check.sh [--no-lint]
set -eu

cd "$(dirname "$0")/.."

echo "== gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "gofmt needed for:"
	echo "$unformatted"
	exit 1
fi

echo "== go vet"
go vet ./...

if [ "${1:-}" != "--no-lint" ]; then
	echo "== golangci-lint"
	if command -v golangci-lint >/dev/null 2>&1; then
		golangci-lint run ./...
	else
		echo "golangci-lint not installed (see CONTRIBUTING.md)"
		exit 1
	fi
fi

echo "== go test"
go test ./...

echo "== documentation pairs (EN/DE)"
missing=0
for doc in README CONTRIBUTING SECURITY; do
	for f in "$doc.md" "$doc.de.md"; do
		if [ ! -f "$f" ]; then
			echo "missing $f"
			missing=1
		fi
	done
done
exit $missing
