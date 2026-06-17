#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ===== Prompt for IMAGE_NAME =====
if [[ -z "${IMAGE_NAME:-}" ]]; then
  IMAGE_NAME="masterking32/masterdnsvpn"
fi

if [[ -z "${IMAGE_NAME}" ]]; then
  echo "IMAGE_NAME cannot be empty" >&2
  exit 1
fi

# ===== Defaults =====
TAG="${TAG:?set TAG to an immutable release tag}"
RELEASE_TAG="${RELEASE_TAG:?set RELEASE_TAG to an immutable release tag}"
RELEASE_SHA256="${RELEASE_SHA256:?set RELEASE_SHA256 for the release archive}"
[[ "${TAG}" != "latest" && "${RELEASE_TAG}" != "latest" ]] || { echo "Mutable latest tags are forbidden" >&2; exit 1; }

case "$(docker version --format '{{.Server.Arch}}')" in
  amd64) SHA_ARG=RELEASE_SHA256_AMD64 ;;
  arm64) SHA_ARG=RELEASE_SHA256_ARM64 ;;
  arm) SHA_ARG=RELEASE_SHA256_ARMV7 ;;
  *) echo "Unsupported local Docker architecture" >&2; exit 1 ;;
esac

# ===== Build (local only) =====
docker build \
  --build-arg RELEASE_TAG="${RELEASE_TAG}" \
  --build-arg "${SHA_ARG}=${RELEASE_SHA256}" \
  -t "${IMAGE_NAME}:${TAG}" \
  -f docker/Dockerfile \
  ..

echo "Local image built successfully: ${IMAGE_NAME}:${TAG}"
