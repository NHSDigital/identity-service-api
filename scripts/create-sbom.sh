REPO_ROOT=$(git rev-parse --show-toplevel)

syft -o spdx-json . > sbom.json

for tool in "$@"; do
  echo "Creating SBOM for $tool and merging"
  syft -q -o spdx-json "$(which "$tool")" | python "$REPO_ROOT/scripts/update-sbom.py"
done