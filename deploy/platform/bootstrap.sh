#!/usr/bin/env bash
#
# shellcheck disable=SC2016,SC2029,SC2089,SC2090
# SC2016/SC2029: literal ${VAR} is intentional (envsubst / client-side ssh expansion).
# SC2089/SC2090: false positives on simple string values passed to awk/export.
#
# bootstrap.sh — idempotent installer for the pdn-shield hackathon stand.
#
# Brings up the whole platform on a clean Ubuntu 24.04 node:
#   k3s + Traefik, Helm, cert-manager + ClusterIssuers, namespace pdn,
#   Redis, HTTPS-redirect middleware, Certificate, kube-prometheus-stack
#   (Prometheus + Grafana + dashboard), Headlamp, the pdn-shield secrets
#   and finally the service itself via `kubectl apply -k deploy/k8s`.
#
# Run locally as root:
#   sudo DOMAIN=alfa-hakaton-prod.ru ACME_EMAIL=you@example.com \
#        GRAFANA_ADMIN_PASSWORD=... ./deploy/platform/bootstrap.sh
#
# Or from a laptop over ssh (script is copied to the node and run there):
#   REMOTE=root@1.2.3.4 DOMAIN=... ACME_EMAIL=... GRAFANA_ADMIN_PASSWORD=... \
#        ./deploy/platform/bootstrap.sh
#
# Every step is idempotent: re-running is safe and only fills gaps.
# Use --dry-run to print what would be done without changing anything.
#
# Required variables:
#   DOMAIN                public domain, e.g. alfa-hakaton-prod.ru
#   ACME_EMAIL            Let's Encrypt account email
#   GRAFANA_ADMIN_PASSWORD  Grafana admin password (never written to files)
#   SERVER_IP             public IP of the node (defaults to DOMAIN's A record)
#
# Optional variables (auto-generated if empty):
#   PDN_ENC_KEY, MODEL_KEY, PDN_DEMO_KEY, PDN_CHATBOT_KEY
#
# Optional:
#   REMOTE                ssh target, e.g. root@1.2.3.4 — run on the node via ssh
#   KUBECONFIG            path to kubeconfig for the final kubectl apply
#   HELM_REPO_*           override helm repo URLs (see defaults below)
#   FORCE_SECRETS         set to 1 to regenerate pdn-shield-secrets even if it
#                         already exists (default: leave an existing secret alone)

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi

DOMAIN="${DOMAIN:?DOMAIN is required, e.g. alfa-hakaton-prod.ru}"
ACME_EMAIL="${ACME_EMAIL:?ACME_EMAIL is required (Let's Encrypt account email)}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:?GRAFANA_ADMIN_PASSWORD is required}"
SERVER_IP="${SERVER_IP:-$(getent hosts "${DOMAIN}" | awk '{print $1; exit}')}"
# shellcheck disable=SC2089,SC2090
if [[ -z "${SERVER_IP}" ]]; then
  echo "!! could not resolve ${DOMAIN} to an IP; set SERVER_IP explicitly" >&2
  exit 1
fi

REMOTE="${REMOTE:-}"
KUBECONFIG="${KUBECONFIG:-}"

HELM_REPO_JETSTACK="${HELM_REPO_JETSTACK:-https://charts.jetstack.io}"
HELM_REPO_PROMETHEUS="${HELM_REPO_PROMETHEUS:-https://prometheus-community.github.io/helm-charts}"
HELM_REPO_HEADLAMP="${HELM_REPO_HEADLAMP:-https://kubernetes-sigs.github.io/headlamp/}"

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.2}"
KUBE_PROMETHEUS_VERSION="${KUBE_PROMETHEUS_VERSION:-91.4.1}"
HEADLAMP_VERSION="${HEADLAMP_VERSION:-0.45.0}"

# Directory this script lives in (works both locally and after scp to the node).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER_DIR="${RENDER_DIR:-/tmp/pdn-platform-render}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '\n\033[1;34m>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

# run <cmd...> — executes, or prints under --dry-run.
run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '   [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

# kubectl wrapper honouring KUBECONFIG.
kc() {
  if [[ -n "${KUBECONFIG}" ]]; then
    kubectl --kubeconfig "${KUBECONFIG}" "$@"
  else
    kubectl "$@"
  fi
}

# helm wrapper honouring KUBECONFIG.
helmc() {
  if [[ -n "${KUBECONFIG}" ]]; then
    helm --kubeconfig "${KUBECONFIG}" "$@"
  else
    helm "$@"
  fi
}

# Render every *.tpl.yaml under deploy/platform into RENDER_DIR via envsubst,
# preserving the relative subdirectory layout so same-named templates (e.g.
# monitoring/values.tpl.yaml and headlamp/values.tpl.yaml) don't collide.
render_templates() {
  log "Rendering templates into ${RENDER_DIR}"
  if ! command -v envsubst >/dev/null 2>&1; then
    log "envsubst not found, installing gettext-base"
    run apt-get update -y
    run apt-get install -y gettext-base
  fi
  run mkdir -p "${RENDER_DIR}"
  export DOMAIN ACME_EMAIL SERVER_IP
  local tpl rel out
  while IFS= read -r -d '' tpl; do
    rel="${tpl#"${SCRIPT_DIR}"/}"
    out="${RENDER_DIR}/${rel%.tpl.yaml}.yaml"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      printf '   [dry-run] envsubst %s -> %s\n' "${tpl}" "${out}"
    else
      mkdir -p "$(dirname "${out}")"
      envsubst '${DOMAIN} ${ACME_EMAIL} ${SERVER_IP}' < "${tpl}" > "${out}"
    fi
  done < <(find "${SCRIPT_DIR}" -name '*.tpl.yaml' -print0)
}

# ---------------------------------------------------------------------------
# Remote mode: copy this script to the node and run it there.
# ---------------------------------------------------------------------------

if [[ -n "${REMOTE}" ]]; then
  log "Running on remote node ${REMOTE}"
  REMOTE_DIR="/tmp/pdn-deploy"
  # deploy/ tree (this script's parent's parent), so the copy preserves the
  # same platform/../k8s layout the script relies on for RENDER_DIR and
  # `kc apply -k`.
  DEPLOY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
  DEPLOY_PARENT="$(dirname "${DEPLOY_ROOT}")"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "   [dry-run] would tar the deploy/ tree to ${REMOTE}:${REMOTE_DIR} and run bootstrap.sh there"
    exit 0
  fi
  # Copy the whole deploy/ tree (platform/ + k8s/), not just this script: the
  # script applies manifests and renders templates relative to its own
  # location, and needs deploy/k8s as a sibling of deploy/platform.
  log "Copying deploy/ tree to ${REMOTE}:${REMOTE_DIR}"
  ssh "${REMOTE}" "mkdir -p '${REMOTE_DIR}'"
  tar -C "${DEPLOY_PARENT}" -czf - deploy | ssh "${REMOTE}" "tar -C '${REMOTE_DIR}' -xzf -"
  # Re-invoke ourselves on the node with the same env, minus REMOTE.
  ssh "${REMOTE}" \
    "DOMAIN='${DOMAIN}' ACME_EMAIL='${ACME_EMAIL}' GRAFANA_ADMIN_PASSWORD='${GRAFANA_ADMIN_PASSWORD}' \
     SERVER_IP='${SERVER_IP}' PDN_ENC_KEY='${PDN_ENC_KEY:-}' MODEL_KEY='${MODEL_KEY:-}' \
     PDN_DEMO_KEY='${PDN_DEMO_KEY:-}' PDN_CHATBOT_KEY='${PDN_CHATBOT_KEY:-}' \
     FORCE_SECRETS='${FORCE_SECRETS:-}' \
     bash '${REMOTE_DIR}/deploy/platform/bootstrap.sh'"
  exit $?
fi

# ---------------------------------------------------------------------------
# 1. System packages + firewall
# ---------------------------------------------------------------------------

log "Step 1/9 — system packages and firewall"
run apt-get update -y
# gettext-base provides envsubst, used by render_templates below.
run apt-get install -y curl git jq ufw gettext-base
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "   [dry-run] ufw allow 22,80,443,6443/tcp and enable"
else
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 6443/tcp
  ufw --force enable
fi

# ---------------------------------------------------------------------------
# 2. k3s
# ---------------------------------------------------------------------------

log "Step 2/9 — k3s"
if command -v k3s >/dev/null 2>&1; then
  echo "   k3s already installed, skipping"
elif [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "   [dry-run] install k3s with --tls-san ${SERVER_IP} --tls-san ${DOMAIN}"
else
  curl -sfL https://get.k3s.io | \
    INSTALL_K3S_EXEC="server --tls-san ${SERVER_IP} --tls-san ${DOMAIN}" sh -
fi
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "   [dry-run] wait for node Ready"
else
  echo "   waiting for node Ready..."
  until kc get nodes 2>/dev/null | grep -q Ready; do sleep 3; done
  echo "   node is Ready"
fi

# ---------------------------------------------------------------------------
# 3. Helm
# ---------------------------------------------------------------------------

log "Step 3/9 — Helm"
if command -v helm >/dev/null 2>&1; then
  echo "   helm already installed, skipping"
else
  run curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# ---------------------------------------------------------------------------
# 4. cert-manager + ClusterIssuers
# ---------------------------------------------------------------------------

log "Step 4/9 — cert-manager"
if helmc repo list 2>/dev/null | grep -q jetstack; then
  echo "   jetstack repo present"
else
  run helmc repo add jetstack "${HELM_REPO_JETSTACK}"
  run helmc repo update
fi
if helmc ls -n cert-manager 2>/dev/null | grep -q cert-manager; then
  echo "   cert-manager release present, skipping install"
else
  run helmc install cert-manager jetstack/cert-manager \
    --namespace cert-manager --create-namespace \
    --version "${CERT_MANAGER_VERSION}" \
    --set installCRDs=true
fi
render_templates
# render_templates preserves the template's subdirectory layout, so both
# cert-manager/*.tpl.yaml files land under RENDER_DIR/cert-manager/.
run kc apply -f "${RENDER_DIR}/cert-manager/cluster-issuers.yaml"

# ---------------------------------------------------------------------------
# 5. namespace pdn, Redis, Middleware, Certificate
# ---------------------------------------------------------------------------

log "Step 5/9 — namespace pdn, Redis, middleware, certificate"
run kc apply -f "${SCRIPT_DIR}/namespace.yaml"
run kc apply -f "${SCRIPT_DIR}/redis.yaml"
run kc apply -f "${SCRIPT_DIR}/traefik/https-redirect.yaml"
run kc apply -f "${RENDER_DIR}/cert-manager/certificate.yaml"

# ---------------------------------------------------------------------------
# 6. kube-prometheus-stack + ServiceMonitor + dashboard + Grafana ingress
# ---------------------------------------------------------------------------

log "Step 6/9 — kube-prometheus-stack"
if helmc repo list 2>/dev/null | grep -q prometheus-community; then
  echo "   prometheus-community repo present"
else
  run helmc repo add prometheus-community "${HELM_REPO_PROMETHEUS}"
  run helmc repo update
fi
if helmc ls -n monitoring 2>/dev/null | grep -q kube-prometheus-stack; then
  echo "   kube-prometheus-stack release present, skipping install"
else
  run helmc install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
    --namespace monitoring --create-namespace \
    --version "${KUBE_PROMETHEUS_VERSION}" \
    --values "${RENDER_DIR}/monitoring/values.yaml" \
    --set grafana.adminPassword="${GRAFANA_ADMIN_PASSWORD}"
fi
run kc apply -f "${SCRIPT_DIR}/monitoring/servicemonitor.yaml"
run kc apply -f "${SCRIPT_DIR}/monitoring/dashboard-configmap.yaml"

# ---------------------------------------------------------------------------
# 7. Headlamp + admin ServiceAccount
# ---------------------------------------------------------------------------

log "Step 7/9 — Headlamp"
if helmc repo list 2>/dev/null | grep -q headlamp; then
  echo "   headlamp repo present"
else
  run helmc repo add headlamp "${HELM_REPO_HEADLAMP}"
  run helmc repo update
fi
if helmc ls -n headlamp 2>/dev/null | grep -q headlamp; then
  echo "   headlamp release present, skipping install"
else
  run helmc install headlamp headlamp/headlamp \
    --namespace headlamp --create-namespace \
    --version "${HEADLAMP_VERSION}" \
    --values "${RENDER_DIR}/headlamp/values.yaml"
fi
run kc apply -f "${SCRIPT_DIR}/headlamp/middleware.yaml"
run kc apply -f "${SCRIPT_DIR}/headlamp/admin.yaml"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "   [dry-run] print headlamp-admin-token at the end"
else
  echo "   Headlamp login token:"
  kc -n headlamp get secret headlamp-admin-token -o jsonpath='{.data.token}' | base64 -d
  echo
fi

# ---------------------------------------------------------------------------
# 8. pdn-shield secrets
# ---------------------------------------------------------------------------

log "Step 8/9 — pdn-shield secrets"
FORCE_SECRETS="${FORCE_SECRETS:-0}"
# Re-running bootstrap must never rotate existing secrets under the app's
# feet (it would silently break decryption of already-stored records and
# invalidate live API keys). Only (re)generate when the secret is missing,
# or when the operator explicitly asks for it via FORCE_SECRETS=1.
SECRET_EXISTS=0
if [[ "${DRY_RUN}" -ne 1 ]] && kc -n pdn get secret pdn-shield-secrets >/dev/null 2>&1; then
  SECRET_EXISTS=1
fi
if [[ "${SECRET_EXISTS}" -eq 1 && "${FORCE_SECRETS}" != "1" ]]; then
  echo "   secret pdn-shield-secrets already exists, skipping (set FORCE_SECRETS=1 to regenerate)"
elif [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "   [dry-run] create/refresh secret pdn-shield-secrets (PDN_ENC_KEY, MODEL_KEY, PDN_DEMO_KEY, PDN_CHATBOT_KEY)"
else
  PDN_ENC_KEY="${PDN_ENC_KEY:-$(openssl rand -hex 32)}"
  MODEL_KEY="${MODEL_KEY:-$(openssl rand -hex 16)}"
  PDN_DEMO_KEY="${PDN_DEMO_KEY:-$(openssl rand -hex 16)}"
  PDN_CHATBOT_KEY="${PDN_CHATBOT_KEY:-$(openssl rand -hex 16)}"
  kc -n pdn create secret generic pdn-shield-secrets \
    --from-literal=PDN_ENC_KEY="${PDN_ENC_KEY}" \
    --from-literal=MODEL_KEY="${MODEL_KEY}" \
    --from-literal=PDN_DEMO_KEY="${PDN_DEMO_KEY}" \
    --from-literal=PDN_CHATBOT_KEY="${PDN_CHATBOT_KEY}" \
    --dry-run=client -o yaml | kc apply -f -
  echo "   secret keys created: PDN_ENC_KEY MODEL_KEY PDN_DEMO_KEY PDN_CHATBOT_KEY (values not printed)"
fi

# ---------------------------------------------------------------------------
# 9. Deploy the service
# ---------------------------------------------------------------------------

log "Step 9/9 — deploy pdn-shield service"
run kc apply -k "${SCRIPT_DIR}/../k8s"
echo
echo "Done. To build and load the image into k3s, run:"
echo "   SERVER=root@${SERVER_IP} make deploy"
echo "Grafana:  https://grafana.${DOMAIN}   (admin / your GRAFANA_ADMIN_PASSWORD)"
echo "Headlamp: https://k8s.${DOMAIN}       (paste the token printed above)"