# kyverno-base

A curated library of [Kyverno](https://kyverno.io) `ClusterPolicy` resources covering pod security, networking, RBAC, workload best practices, and label standards. All policies use CEL-based validation and are tested end-to-end with [Chainsaw](https://kyverno.github.io/chainsaw/).

## Prerequisites

| Tool | Minimum version | Install |
|------|----------------|---------|
| Kubernetes | 1.34 | — |
| Kyverno | 1.16.2 | [docs](https://kyverno.io/docs/installation/) |
| Chainsaw | latest | `go install github.com/kyverno/chainsaw@latest` |

## Installation

Apply a single category:

```bash
kubectl apply -f pod-security/
```

Apply all policies at once:

```bash
kubectl apply -R -f .
```

> **Note:** policies exclude the `kube-system` and `kyverno` namespaces by default.

## Running Tests

All policies are validated with Chainsaw against a live cluster (or [kind](https://kind.sigs.k8s.io/)).

```bash
chainsaw test
```

Test a single category:

```bash
chainsaw test pod-security/
```

## Policy Reference

### Labels

| Policy | Severity | Subjects | Description |
|--------|----------|----------|-------------|
| `require-standard-labels` | low | Pod | Requires `app.kubernetes.io/name` and `app.kubernetes.io/version` labels on every pod. |

### Networking

| Policy | Severity | Subjects | Description |
|--------|----------|----------|-------------|
| `disallow-ingress-without-host` | medium | Ingress | Every Ingress rule must specify a non-blank hostname. |
| `disallow-nodeport-services` | medium | Service | Services of type `NodePort` are not allowed; use `ClusterIP` with an Ingress. |
| `disallow-wildcard-ingress` | medium | Ingress | Ingress hostnames must not contain a wildcard (`*`). |

### Pod Security

| Policy | Severity | Subjects | Description |
|--------|----------|----------|-------------|
| `disallow-host-namespaces` | high | Pod | Pods must not set `hostPID`, `hostIPC`, or `hostNetwork`. |
| `disallow-privilege-escalation` | high | Pod | All containers must set `allowPrivilegeEscalation: false`. |
| `disallow-privileged-containers` | high | Pod | Containers must not run with `privileged: true`. |
| `disallow-root-user` | medium | Pod | Containers must run as a non-root user (`runAsNonRoot: true` or `runAsUser > 0`). |
| `require-readonly-rootfs` | medium | Pod | All containers must set `readOnlyRootFilesystem: true`. |

### RBAC

| Policy | Severity | Subjects | Description |
|--------|----------|----------|-------------|
| `disallow-cluster-admin-binding` | high | ClusterRoleBinding, RoleBinding | Bindings to the `cluster-admin` role are not allowed. |
| `disallow-wildcard-verbs` | high | ClusterRole, Role | Roles must not use `*` in `verbs` or `resources`. |

### Workload Best Practices

| Policy | Severity | Subjects | Description |
|--------|----------|----------|-------------|
| `disallow-latest-image-tag` | medium | Pod | Container images must specify an explicit, non-`latest` tag. |
| `require-liveness-probe` | low | Pod | All containers must define a `livenessProbe`. |
| `require-readiness-probe` | low | Pod | All containers must define a `readinessProbe`. |
| `require-resource-limits` | medium | Pod | All containers must set CPU and memory `requests` and `limits`. |

## Repository Layout

```
.
├── labels/
├── networking/
├── pod-security/
├── rbac/
└── workload-best-practices/
```

Each subdirectory contains one folder per policy. Each policy folder holds `policy.yaml` and a `.chainsaw-test/` directory with valid and invalid test fixtures.
