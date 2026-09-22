#!/usr/bin/env bash
set -euo pipefail

# Build the image locally and load it into the k3s node, then roll the
# deployment. Requires: SERVER (ssh host), optional TAG (defaults to the git
# short sha) and KUBECONFIG (defaults to the local kubeconfig).

SERVER="${SERVER:?SERVER is required, e.g. root@1.2.3.4}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
KUBECONFIG="${KUBECONFIG:-}"
PLATFORM="${PLATFORM:-linux/amd64}"

IMAGE="pdn-shield:${TAG}"

echo ">> building ${IMAGE} for ${PLATFORM}"
docker build --platform "${PLATFORM}" -t "${IMAGE}" .

echo ">> loading ${IMAGE} into k3s on ${SERVER}"
docker save "${IMAGE}" | ssh "${SERVER}" 'k3s ctr images import -'

KUBECTL=(kubectl)
if [ -n "${KUBECONFIG}" ]; then
  KUBECTL=(kubectl --kubeconfig "${KUBECONFIG}")
fi

echo ">> rolling deployment to ${IMAGE}"
"${KUBECTL[@]}" -n pdn set image deployment/pdn-shield pdn-shield="${IMAGE}"
"${KUBECTL[@]}" -n pdn rollout status deployment/pdn-shield

echo ">> done"