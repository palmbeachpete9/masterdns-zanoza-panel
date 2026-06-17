#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

RELEASE_TAG="${RELEASE_TAG:?set RELEASE_TAG to an immutable release tag}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm/v5,linux/arm/v7,linux/arm64/v8,linux/mips64le}"
REGISTRY_KIND="${REGISTRY_KIND:-ghcr}"
IMAGE_REFS_CSV="${IMAGE_REFS:?set IMAGE_REFS to immutable release tags}"
RELEASE_SHA256_AMD64="${RELEASE_SHA256_AMD64:?set RELEASE_SHA256_AMD64}"
RELEASE_SHA256_ARM64="${RELEASE_SHA256_ARM64:?set RELEASE_SHA256_ARM64}"
RELEASE_SHA256_ARMV5="${RELEASE_SHA256_ARMV5:?set RELEASE_SHA256_ARMV5}"
RELEASE_SHA256_ARMV7="${RELEASE_SHA256_ARMV7:?set RELEASE_SHA256_ARMV7}"
RELEASE_SHA256_MIPS64LE="${RELEASE_SHA256_MIPS64LE:?set RELEASE_SHA256_MIPS64LE}"
[[ "${RELEASE_TAG}" != "latest" ]] || { echo "Mutable latest release tag is forbidden" >&2; exit 1; }

if ! docker buildx version >/dev/null 2>&1; then
  echo "docker buildx is required" >&2
  exit 1
fi

case "${REGISTRY_KIND}" in
  dockerhub)
    REGISTRY_HOST=""
    ;;
  ghcr)
    REGISTRY_HOST="ghcr.io"
    ;;
  *)
    echo "Invalid REGISTRY_KIND=${REGISTRY_KIND}. Use dockerhub or ghcr." >&2
    exit 1
    ;;
esac

validate_image_ref() {
  local ref="$1"
  local re='^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(:[A-Za-z0-9._-][A-Za-z0-9._-]{0,127})?$'
  [[ "$ref" =~ ${re} ]]
}

IMAGE_REFS=()
IFS=',' read -r -a RAW_REFS <<< "${IMAGE_REFS_CSV}"
for RAW_REF in "${RAW_REFS[@]}"; do
  REF="$(echo "${RAW_REF}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [[ -z "${REF}" ]]; then
    continue
  fi
  if ! validate_image_ref "${REF}"; then
    echo "Invalid image ref: ${REF}" >&2
    exit 1
  fi
  LAST_COMPONENT="${REF##*/}"
  [[ "${LAST_COMPONENT}" == *:* ]] || { echo "Image ref must contain an immutable release tag: ${REF}" >&2; exit 1; }
  IMAGE_TAG="${LAST_COMPONENT##*:}"
  [[ -n "${IMAGE_TAG}" && "${IMAGE_TAG}" != "latest" ]] || { echo "Mutable/empty image tag is forbidden: ${REF}" >&2; exit 1; }
  IMAGE_REFS+=("${REF}")
done

if [[ "${#IMAGE_REFS[@]}" -eq 0 ]]; then
  echo "At least one image name is required." >&2
  exit 1
fi

if [[ "${REGISTRY_KIND}" == "dockerhub" ]]; then
  if [[ -n "${DOCKER_USERNAME:-}" && -n "${DOCKER_PASSWORD:-}" ]]; then
    echo "${DOCKER_PASSWORD}" | docker login --username "${DOCKER_USERNAME}" --password-stdin
  else
    echo "Docker Hub login vars not provided, assuming already logged in."
  fi
else
  if [[ -n "${GHCR_USERNAME:-}" && -n "${GHCR_TOKEN:-}" ]]; then
    echo "${GHCR_TOKEN}" | docker login ghcr.io --username "${GHCR_USERNAME}" --password-stdin
  else
    echo "GHCR login vars not provided, assuming already logged in."
  fi
fi

TAG_ARGS=()
for REF in "${IMAGE_REFS[@]}"; do
  if [[ "${REGISTRY_KIND}" == "ghcr" ]]; then
    REF="${REGISTRY_HOST}/${REF}"
  fi
  TAG_ARGS+=(-t "${REF}")
done

docker buildx build \
  --platform "${PLATFORMS}" \
  --build-arg RELEASE_TAG="${RELEASE_TAG}" \
  --build-arg RELEASE_SHA256_AMD64="${RELEASE_SHA256_AMD64}" \
  --build-arg RELEASE_SHA256_ARM64="${RELEASE_SHA256_ARM64}" \
  --build-arg RELEASE_SHA256_ARMV5="${RELEASE_SHA256_ARMV5}" \
  --build-arg RELEASE_SHA256_ARMV7="${RELEASE_SHA256_ARMV7}" \
  --build-arg RELEASE_SHA256_MIPS64LE="${RELEASE_SHA256_MIPS64LE}" \
  "${TAG_ARGS[@]}" \
  -f docker/Dockerfile \
  --push \
  ..

echo
echo "Build and push completed:"
for REF in "${IMAGE_REFS[@]}"; do
  if [[ "${REGISTRY_KIND}" == "ghcr" ]]; then
    REF="ghcr.io/${REF}"
  fi
  echo "  ${REF}"
done
