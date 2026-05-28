# GitHub Actions Self-Hosted Runner Setup (EKS)

## Prerequisites

- EKS cluster is running and `kubectl` is configured
- Helm 3 installed
- GitHub PAT with the following **required** permissions:
  - `repo` (Full control of private repositories)
  - `admin:org` (if using org-level runners)

## Step 1: Install cert-manager (required by ARC)

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.5/cert-manager.yaml
kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=120s
```

## Step 2: Install Actions Runner Controller (ARC)

```bash
helm repo add actions-runner-controller https://actions-runner-controller.github.io/actions-runner-controller
helm repo update

helm install actions-runner-controller actions-runner-controller/actions-runner-controller \
  --namespace actions-runner-system \
  --create-namespace \
  --set authSecret.create=true \
  --set authSecret.github_token="<YOUR_GITHUB_PAT>" \
  --wait
```

## Step 3: Verify the controller is running

```bash
kubectl get pods -n actions-runner-system
# You should see the controller-manager pod in Running state
```

## Step 4: Apply the RunnerDeployment

```bash
kubectl apply -f runner-deployment.yaml
```

## Step 5: Verify runners are registered

```bash
kubectl get runners -n actions-runner-system
# Runners should show as "Running" and appear in GitHub repo Settings > Actions > Runners
```

## Troubleshooting

### Token is valid but missing REQUIRED permissions

Your GitHub PAT needs these scopes:
- **`repo`** — required to register runners at the repository level
- **`admin:org`** — required only if registering org-level runners

To fix: regenerate the PAT with correct scopes and update the secret:

```bash
kubectl delete secret controller-manager -n actions-runner-system
kubectl create secret generic controller-manager \
  --namespace=actions-runner-system \
  --from-literal=github_token=<NEW_PAT>
# Restart the controller
kubectl rollout restart deployment actions-runner-controller -n actions-runner-system
```

### RunnerDeployment is not being reconciled

Common causes:
1. **Controller not installed** — ARC must be installed via Helm first
2. **Missing secret** — The `controller-manager` secret must exist in `actions-runner-system`
3. **Missing labels/selector** — The RunnerDeployment needs matching `selector.matchLabels`
4. **cert-manager not ready** — ARC depends on cert-manager for webhook certificates

Check controller logs:
```bash
kubectl logs -n actions-runner-system deployment/actions-runner-controller -f
```
