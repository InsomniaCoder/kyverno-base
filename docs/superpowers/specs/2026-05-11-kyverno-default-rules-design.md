# Kyverno Base — Default Cluster Guardrails

**Date:** 2026-05-11  
**Status:** Approved

## Overview

A repository of default Kyverno policies that every cluster should have as sane baseline guardrails. All policies are CEL-based, set to `Enforce`, and each ships with a Chainsaw integration test.

---

## Repository Structure

```
kyverno-base/
├── .chainsaw.yaml
├── pod-security/
│   ├── disallow-privileged-containers/
│   ├── disallow-host-namespaces/
│   ├── disallow-privilege-escalation/
│   ├── disallow-root-user/
│   └── require-readonly-rootfs/
├── workload-best-practices/
│   ├── require-resource-limits/
│   ├── require-liveness-probe/
│   ├── require-readiness-probe/
│   └── disallow-latest-image-tag/
├── networking/
│   ├── disallow-wildcard-ingress/
│   ├── disallow-ingress-without-host/
│   └── disallow-nodeport-services/
├── rbac/
│   ├── disallow-wildcard-verbs/
│   └── disallow-cluster-admin-binding/
└── labels/
    └── require-standard-labels/
```

Each leaf directory contains:
- `policy.yaml` — the `ClusterPolicy` resource
- `.chainsaw-test/chainsaw-test.yaml` — the Chainsaw test definition
- `.chainsaw-test/valid-<resource>.yaml` — resource(s) that must pass
- `.chainsaw-test/invalid-<violation>.yaml` — resource(s) that must be blocked (one file per distinct violation type)

---

## Target Versions

| Component  | Version |
|------------|---------|
| Kyverno    | 1.16.2  |
| Kubernetes | 1.34    |

---

## Policy Conventions

### ClusterPolicy shape

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: <kebab-case-name>
  annotations:
    policies.kyverno.io/title: <Human Readable Title>
    policies.kyverno.io/category: <Pod Security | Workload Best Practices | Networking | RBAC | Labels>
    policies.kyverno.io/severity: <low | medium | high>
    policies.kyverno.io/subject: <Pod | Ingress | Service | ClusterRole | ...>
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      One paragraph explaining what the policy enforces and why.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: <rule-name>
      match:
        any:
          - resources:
              kinds: [<Kind>]
              operations: [CREATE, UPDATE]
      celPreconditions: []      # only when needed to narrow scope
      validate:
        cel:
          expressions:
            - expression: "<CEL expression>"
              message: "<actionable error message telling user what to fix>"
```

### Rules

- All policies use `validate.cel` — no JMESPath-based rules.
- `validationFailureAction: Enforce` on every policy.
- `background: false` by default; set `true` only for policies that meaningfully scan existing resources.
- `operations: [CREATE, UPDATE]` explicitly stated on every rule.
- `celPreconditions` used only when needed to narrow scope (e.g., skip resources that lack a particular field).
- Error messages are actionable — they state what to fix, not just what failed.

---

## Chainsaw Test Conventions

### Root `.chainsaw.yaml`

Shared configuration for all tests:

```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Configuration
metadata:
  name: configuration
spec:
  parallel: 1
  timeouts:
    apply: 2m
    assert: 2m
    cleanup: 2m
    delete: 2m
    error: 2m
    exec: 2m
  fullName: true
  forceTerminationGracePeriod: 10s
  delayBeforeCleanup: 10s
```

### Per-policy test shape

```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: <policy-name>
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml

    - name: 02 - Valid <resource> should be allowed
      try:
        - apply:
            file: valid-<resource>.yaml
            expect:
              - check:
                  ($error == null): true

    - name: 03 - <Violation description> should be blocked
      try:
        - apply:
            file: invalid-<violation>.yaml
            expect:
              - check:
                  ($error != null): true
```

### Rules

- Steps numbered `01`, `02`, `03` for clear ordering.
- One `valid-*.yaml` covering the happy path.
- Separate `invalid-*.yaml` per distinct violation type.
- Test file names are descriptive of the violation they represent.

---

## Policy Inventory

### Pod Security

| Policy | Subject | What it enforces |
|--------|---------|-----------------|
| `disallow-privileged-containers` | Pod | No container may set `securityContext.privileged: true` |
| `disallow-host-namespaces` | Pod | `hostPID`, `hostIPC`, `hostNetwork` must all be false |
| `disallow-privilege-escalation` | Pod | All containers must set `allowPrivilegeEscalation: false` |
| `disallow-root-user` | Pod | All containers must set `runAsNonRoot: true` or `runAsUser > 0` |
| `require-readonly-rootfs` | Pod | All containers must set `readOnlyRootFilesystem: true` |

### Workload Best Practices

| Policy | Subject | What it enforces |
|--------|---------|-----------------|
| `require-resource-limits` | Pod | All containers must define `resources.requests` and `resources.limits` for CPU and memory |
| `require-liveness-probe` | Pod | All containers must define a `livenessProbe` |
| `require-readiness-probe` | Pod | All containers must define a `readinessProbe` |
| `disallow-latest-image-tag` | Pod | Container images must not use the `latest` tag or omit a tag entirely |

### Networking

| Policy | Subject | What it enforces |
|--------|---------|-----------------|
| `disallow-wildcard-ingress` | Ingress | No Ingress rule may use a wildcard (`*`) hostname |
| `disallow-ingress-without-host` | Ingress | Every Ingress rule must specify a non-blank host |
| `disallow-nodeport-services` | Service | Services may not use `type: NodePort` |

### RBAC

| Policy | Subject | What it enforces |
|--------|---------|-----------------|
| `disallow-wildcard-verbs` | ClusterRole / Role | No rule may use `*` as a verb or resource |
| `disallow-cluster-admin-binding` | ClusterRoleBinding | No binding may reference the `cluster-admin` ClusterRole |

### Labels

| Policy | Subject | What it enforces |
|--------|---------|-----------------|
| `require-standard-labels` | Pod | Pods must carry `app.kubernetes.io/name` and `app.kubernetes.io/version` labels |

---

## Out of Scope

- Mutation policies (image tag rewriting, label injection) — validate only.
- Company-specific or infrastructure-specific policies (Karpenter, cert-manager, ArgoCD).
- Helm chart packaging — raw YAML files only; consumers apply with `kubectl` or their own delivery mechanism.
