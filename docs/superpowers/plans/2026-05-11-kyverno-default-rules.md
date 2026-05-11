# Kyverno Base — Default Cluster Guardrails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a repository of 15 default CEL-based Kyverno ClusterPolicies across 5 categories, each with a Chainsaw integration test.

**Architecture:** Each policy lives in its own directory under its category folder (`pod-security/`, `workload-best-practices/`, `networking/`, `rbac/`, `labels/`). Every directory contains `policy.yaml` and a `.chainsaw-test/` subfolder with the Chainsaw test definition and fixture files. A root `.chainsaw.yaml` provides shared test configuration.

**Tech Stack:** Kyverno 1.16.2, Kubernetes 1.34, Chainsaw (chainsaw.kyverno.io), KIND (local cluster), Helm

---

## File Map

| File | Purpose |
|------|---------|
| `.chainsaw.yaml` | Shared Chainsaw config (timeouts, parallelism) |
| `<category>/<policy>/policy.yaml` | ClusterPolicy resource |
| `<category>/<policy>/.chainsaw-test/chainsaw-test.yaml` | Chainsaw test definition |
| `<category>/<policy>/.chainsaw-test/valid-*.yaml` | Resource that must be admitted |
| `<category>/<policy>/.chainsaw-test/invalid-*.yaml` | Resource that must be blocked |

---

## Task 1: Repository Scaffold

**Files:**
- Create: `.chainsaw.yaml`

- [ ] **Step 1: Create the root Chainsaw configuration**

Save as `.chainsaw.yaml` in the repo root:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/kyverno/chainsaw/main/.schemas/json/configuration-chainsaw-v1alpha1.json
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Configuration
metadata:
  creationTimestamp: null
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

- [ ] **Step 2: Create the category directory structure**

```bash
mkdir -p pod-security/disallow-privileged-containers/.chainsaw-test
mkdir -p pod-security/disallow-host-namespaces/.chainsaw-test
mkdir -p pod-security/disallow-privilege-escalation/.chainsaw-test
mkdir -p pod-security/disallow-root-user/.chainsaw-test
mkdir -p pod-security/require-readonly-rootfs/.chainsaw-test
mkdir -p workload-best-practices/require-resource-limits/.chainsaw-test
mkdir -p workload-best-practices/require-liveness-probe/.chainsaw-test
mkdir -p workload-best-practices/require-readiness-probe/.chainsaw-test
mkdir -p workload-best-practices/disallow-latest-image-tag/.chainsaw-test
mkdir -p networking/disallow-wildcard-ingress/.chainsaw-test
mkdir -p networking/disallow-ingress-without-host/.chainsaw-test
mkdir -p networking/disallow-nodeport-services/.chainsaw-test
mkdir -p rbac/disallow-wildcard-verbs/.chainsaw-test
mkdir -p rbac/disallow-cluster-admin-binding/.chainsaw-test
mkdir -p labels/require-standard-labels/.chainsaw-test
```

- [ ] **Step 3: Commit**

```bash
git init
git add .chainsaw.yaml
git commit -m "chore: initialize repo with chainsaw configuration"
```

---

## Task 2: Local Cluster Setup (dev environment — no committed files)

- [ ] **Step 1: Install chainsaw CLI**

```bash
brew install kyverno/tap/chainsaw
chainsaw version
# Expected: chainsaw version vX.Y.Z
```

- [ ] **Step 2: Create a KIND cluster**

```bash
kind create cluster --name kyverno-base
kubectl cluster-info --context kind-kyverno-base
# Expected: Kubernetes control plane running
```

- [ ] **Step 3: Install Kyverno via Helm**

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --wait
kubectl get pods -n kyverno
# Expected: all pods Running (admission-controller, background-controller, cleanup-controller, reports-controller)
```

---

## Task 3: pod-security/disallow-privileged-containers

**Files:**
- Create: `pod-security/disallow-privileged-containers/.chainsaw-test/valid-pod.yaml`
- Create: `pod-security/disallow-privileged-containers/.chainsaw-test/invalid-privileged.yaml`
- Create: `pod-security/disallow-privileged-containers/.chainsaw-test/chainsaw-test.yaml`
- Create: `pod-security/disallow-privileged-containers/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`pod-security/disallow-privileged-containers/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
```

`pod-security/disallow-privileged-containers/.chainsaw-test/invalid-privileged.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-privileged
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: true
```

- [ ] **Step 2: Write the Chainsaw test**

`pod-security/disallow-privileged-containers/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-privileged-containers
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Non-privileged pod should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Privileged container should be blocked
      try:
        - apply:
            file: invalid-privileged.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test pod-security/disallow-privileged-containers
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`pod-security/disallow-privileged-containers/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Privileged containers have access to all Linux kernel capabilities and devices.
      Running a container as privileged is equivalent to running as root on the host.
      This policy disallows privileged containers in all non-system namespaces.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-privileged-containers
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.containers.all(c,
                  !has(c.securityContext) ||
                  !has(c.securityContext.privileged) ||
                  c.securityContext.privileged == false
                ) &&
                (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
                  !has(c.securityContext) ||
                  !has(c.securityContext.privileged) ||
                  c.securityContext.privileged == false
                ))
              message: "Privileged containers are not allowed. Remove securityContext.privileged or set it to false."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test pod-security/disallow-privileged-containers
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add pod-security/disallow-privileged-containers/
git commit -m "feat: add disallow-privileged-containers policy"
```

---

## Task 4: pod-security/disallow-host-namespaces

**Files:**
- Create: `pod-security/disallow-host-namespaces/.chainsaw-test/valid-pod.yaml`
- Create: `pod-security/disallow-host-namespaces/.chainsaw-test/invalid-host-pid.yaml`
- Create: `pod-security/disallow-host-namespaces/.chainsaw-test/invalid-host-network.yaml`
- Create: `pod-security/disallow-host-namespaces/.chainsaw-test/chainsaw-test.yaml`
- Create: `pod-security/disallow-host-namespaces/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`pod-security/disallow-host-namespaces/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
```

`pod-security/disallow-host-namespaces/.chainsaw-test/invalid-host-pid.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-host-pid
spec:
  hostPID: true
  containers:
    - name: app
      image: nginx:1.25
```

`pod-security/disallow-host-namespaces/.chainsaw-test/invalid-host-network.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-host-network
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
```

- [ ] **Step 2: Write the Chainsaw test**

`pod-security/disallow-host-namespaces/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-host-namespaces
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod without host namespaces should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod with hostPID should be blocked
      try:
        - apply:
            file: invalid-host-pid.yaml
            expect:
              - check:
                  ($error != null): true
    - name: 04 - Pod with hostNetwork should be blocked
      try:
        - apply:
            file: invalid-host-network.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test pod-security/disallow-host-namespaces
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`pod-security/disallow-host-namespaces/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-namespaces
  annotations:
    policies.kyverno.io/title: Disallow Host Namespaces
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Host namespaces (hostPID, hostIPC, hostNetwork) allow pods to share the host's
      process, IPC, and network namespaces, which enables privilege escalation and
      host compromise. This policy disallows pods from using any host namespace.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-host-namespaces
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                (!has(object.spec.hostPID) || object.spec.hostPID == false) &&
                (!has(object.spec.hostIPC) || object.spec.hostIPC == false) &&
                (!has(object.spec.hostNetwork) || object.spec.hostNetwork == false)
              message: "Pods must not use host namespaces. Remove or set hostPID, hostIPC, and hostNetwork to false."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test pod-security/disallow-host-namespaces
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add pod-security/disallow-host-namespaces/
git commit -m "feat: add disallow-host-namespaces policy"
```

---

## Task 5: pod-security/disallow-privilege-escalation

**Files:**
- Create: `pod-security/disallow-privilege-escalation/.chainsaw-test/valid-pod.yaml`
- Create: `pod-security/disallow-privilege-escalation/.chainsaw-test/invalid-no-restriction.yaml`
- Create: `pod-security/disallow-privilege-escalation/.chainsaw-test/chainsaw-test.yaml`
- Create: `pod-security/disallow-privilege-escalation/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`pod-security/disallow-privilege-escalation/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        allowPrivilegeEscalation: false
```

`pod-security/disallow-privilege-escalation/.chainsaw-test/invalid-no-restriction.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-no-restriction
spec:
  containers:
    - name: app
      image: nginx:1.25
```

- [ ] **Step 2: Write the Chainsaw test**

`pod-security/disallow-privilege-escalation/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-privilege-escalation
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with allowPrivilegeEscalation false should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod without allowPrivilegeEscalation false should be blocked
      try:
        - apply:
            file: invalid-no-restriction.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test pod-security/disallow-privilege-escalation
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`pod-security/disallow-privilege-escalation/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privilege-escalation
  annotations:
    policies.kyverno.io/title: Disallow Privilege Escalation
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Privilege escalation allows a process to gain more privileges than its parent.
      This policy requires all containers to explicitly set allowPrivilegeEscalation
      to false to prevent processes from gaining additional privileges at runtime.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-privilege-escalation
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.containers.all(c,
                  has(c.securityContext) &&
                  has(c.securityContext.allowPrivilegeEscalation) &&
                  c.securityContext.allowPrivilegeEscalation == false
                ) &&
                (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
                  has(c.securityContext) &&
                  has(c.securityContext.allowPrivilegeEscalation) &&
                  c.securityContext.allowPrivilegeEscalation == false
                ))
              message: "All containers must set securityContext.allowPrivilegeEscalation: false."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test pod-security/disallow-privilege-escalation
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add pod-security/disallow-privilege-escalation/
git commit -m "feat: add disallow-privilege-escalation policy"
```

---

## Task 6: pod-security/disallow-root-user

**Files:**
- Create: `pod-security/disallow-root-user/.chainsaw-test/valid-pod.yaml`
- Create: `pod-security/disallow-root-user/.chainsaw-test/invalid-root-user.yaml`
- Create: `pod-security/disallow-root-user/.chainsaw-test/chainsaw-test.yaml`
- Create: `pod-security/disallow-root-user/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`pod-security/disallow-root-user/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
```

`pod-security/disallow-root-user/.chainsaw-test/invalid-root-user.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-root-user
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        runAsUser: 0
```

- [ ] **Step 2: Write the Chainsaw test**

`pod-security/disallow-root-user/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-root-user
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with non-root user should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod running as root (uid 0) should be blocked
      try:
        - apply:
            file: invalid-root-user.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test pod-security/disallow-root-user
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`pod-security/disallow-root-user/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-root-user
  annotations:
    policies.kyverno.io/title: Disallow Root User
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Running containers as the root user (UID 0) gives them the same privileges as root
      on the host if they escape the container. This policy requires each container to
      either set runAsNonRoot: true or use a non-zero runAsUser at the container level,
      or have the pod-level runAsNonRoot: true set.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-root-user
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.containers.all(c,
                  (has(object.spec.securityContext) &&
                   has(object.spec.securityContext.runAsNonRoot) &&
                   object.spec.securityContext.runAsNonRoot == true) ||
                  (has(c.securityContext) &&
                   has(c.securityContext.runAsNonRoot) &&
                   c.securityContext.runAsNonRoot == true) ||
                  (has(c.securityContext) &&
                   has(c.securityContext.runAsUser) &&
                   c.securityContext.runAsUser > 0)
                )
              message: "Containers must not run as root. Set runAsNonRoot: true or runAsUser to a non-zero value."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test pod-security/disallow-root-user
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add pod-security/disallow-root-user/
git commit -m "feat: add disallow-root-user policy"
```

---

## Task 7: pod-security/require-readonly-rootfs

**Files:**
- Create: `pod-security/require-readonly-rootfs/.chainsaw-test/valid-pod.yaml`
- Create: `pod-security/require-readonly-rootfs/.chainsaw-test/invalid-writable-rootfs.yaml`
- Create: `pod-security/require-readonly-rootfs/.chainsaw-test/chainsaw-test.yaml`
- Create: `pod-security/require-readonly-rootfs/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`pod-security/require-readonly-rootfs/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        readOnlyRootFilesystem: true
```

`pod-security/require-readonly-rootfs/.chainsaw-test/invalid-writable-rootfs.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-writable-rootfs
spec:
  containers:
    - name: app
      image: nginx:1.25
```

- [ ] **Step 2: Write the Chainsaw test**

`pod-security/require-readonly-rootfs/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: require-readonly-rootfs
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with readOnlyRootFilesystem true should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod without readOnlyRootFilesystem true should be blocked
      try:
        - apply:
            file: invalid-writable-rootfs.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test pod-security/require-readonly-rootfs
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`pod-security/require-readonly-rootfs/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-rootfs
  annotations:
    policies.kyverno.io/title: Require Read-Only Root Filesystem
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      A read-only root filesystem prevents container processes from writing to the
      container's filesystem, limiting the blast radius of a compromised container.
      This policy requires all containers to set readOnlyRootFilesystem: true.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: require-readonly-rootfs
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.containers.all(c,
                  has(c.securityContext) &&
                  has(c.securityContext.readOnlyRootFilesystem) &&
                  c.securityContext.readOnlyRootFilesystem == true
                )
              message: "All containers must set securityContext.readOnlyRootFilesystem: true."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test pod-security/require-readonly-rootfs
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add pod-security/require-readonly-rootfs/
git commit -m "feat: add require-readonly-rootfs policy"
```

---

## Task 8: workload-best-practices/require-resource-limits

**Files:**
- Create: `workload-best-practices/require-resource-limits/.chainsaw-test/valid-pod.yaml`
- Create: `workload-best-practices/require-resource-limits/.chainsaw-test/invalid-no-limits.yaml`
- Create: `workload-best-practices/require-resource-limits/.chainsaw-test/chainsaw-test.yaml`
- Create: `workload-best-practices/require-resource-limits/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`workload-best-practices/require-resource-limits/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
        limits:
          cpu: "200m"
          memory: "256Mi"
```

`workload-best-practices/require-resource-limits/.chainsaw-test/invalid-no-limits.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-no-limits
spec:
  containers:
    - name: app
      image: nginx:1.25
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
```

- [ ] **Step 2: Write the Chainsaw test**

`workload-best-practices/require-resource-limits/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: require-resource-limits
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with cpu and memory requests and limits should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod without resource limits should be blocked
      try:
        - apply:
            file: invalid-no-limits.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test workload-best-practices/require-resource-limits
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`workload-best-practices/require-resource-limits/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
  annotations:
    policies.kyverno.io/title: Require Resource Requests and Limits
    policies.kyverno.io/category: Workload Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Resource requests and limits prevent containers from consuming unbounded CPU and
      memory, which can starve other workloads. This policy requires all containers to
      specify cpu and memory for both requests and limits.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: require-resource-limits
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.containers.all(c,
                  has(c.resources) &&
                  has(c.resources.requests) &&
                  'cpu' in c.resources.requests &&
                  'memory' in c.resources.requests &&
                  has(c.resources.limits) &&
                  'cpu' in c.resources.limits &&
                  'memory' in c.resources.limits
                )
              message: "All containers must specify resources.requests and resources.limits for both cpu and memory."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test workload-best-practices/require-resource-limits
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add workload-best-practices/require-resource-limits/
git commit -m "feat: add require-resource-limits policy"
```

---

## Task 9: workload-best-practices/require-liveness-probe

**Files:**
- Create: `workload-best-practices/require-liveness-probe/.chainsaw-test/valid-pod.yaml`
- Create: `workload-best-practices/require-liveness-probe/.chainsaw-test/invalid-no-probe.yaml`
- Create: `workload-best-practices/require-liveness-probe/.chainsaw-test/chainsaw-test.yaml`
- Create: `workload-best-practices/require-liveness-probe/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`workload-best-practices/require-liveness-probe/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      livenessProbe:
        httpGet:
          path: /healthz
          port: 80
        initialDelaySeconds: 10
        periodSeconds: 10
```

`workload-best-practices/require-liveness-probe/.chainsaw-test/invalid-no-probe.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-no-probe
spec:
  containers:
    - name: app
      image: nginx:1.25
```

- [ ] **Step 2: Write the Chainsaw test**

`workload-best-practices/require-liveness-probe/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: require-liveness-probe
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with livenessProbe should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod without livenessProbe should be blocked
      try:
        - apply:
            file: invalid-no-probe.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test workload-best-practices/require-liveness-probe
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`workload-best-practices/require-liveness-probe/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-liveness-probe
  annotations:
    policies.kyverno.io/title: Require Liveness Probe
    policies.kyverno.io/category: Workload Best Practices
    policies.kyverno.io/severity: low
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Liveness probes allow Kubernetes to detect when a container is in a broken state
      and restart it automatically. Without a liveness probe, a deadlocked or hung
      container will not be restarted. This policy requires all containers to define
      a livenessProbe.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: require-liveness-probe
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: "object.spec.containers.all(c, has(c.livenessProbe))"
              message: "All containers must define a livenessProbe."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test workload-best-practices/require-liveness-probe
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add workload-best-practices/require-liveness-probe/
git commit -m "feat: add require-liveness-probe policy"
```

---

## Task 10: workload-best-practices/require-readiness-probe

**Files:**
- Create: `workload-best-practices/require-readiness-probe/.chainsaw-test/valid-pod.yaml`
- Create: `workload-best-practices/require-readiness-probe/.chainsaw-test/invalid-no-probe.yaml`
- Create: `workload-best-practices/require-readiness-probe/.chainsaw-test/chainsaw-test.yaml`
- Create: `workload-best-practices/require-readiness-probe/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`workload-best-practices/require-readiness-probe/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25
      readinessProbe:
        httpGet:
          path: /ready
          port: 80
        initialDelaySeconds: 5
        periodSeconds: 10
```

`workload-best-practices/require-readiness-probe/.chainsaw-test/invalid-no-probe.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-no-probe
spec:
  containers:
    - name: app
      image: nginx:1.25
```

- [ ] **Step 2: Write the Chainsaw test**

`workload-best-practices/require-readiness-probe/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: require-readiness-probe
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with readinessProbe should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod without readinessProbe should be blocked
      try:
        - apply:
            file: invalid-no-probe.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test workload-best-practices/require-readiness-probe
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`workload-best-practices/require-readiness-probe/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readiness-probe
  annotations:
    policies.kyverno.io/title: Require Readiness Probe
    policies.kyverno.io/category: Workload Best Practices
    policies.kyverno.io/severity: low
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Readiness probes tell Kubernetes when a container is ready to receive traffic.
      Without a readiness probe, traffic may be sent to a container before it has
      finished initializing. This policy requires all containers to define a readinessProbe.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: require-readiness-probe
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: "object.spec.containers.all(c, has(c.readinessProbe))"
              message: "All containers must define a readinessProbe."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test workload-best-practices/require-readiness-probe
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add workload-best-practices/require-readiness-probe/
git commit -m "feat: add require-readiness-probe policy"
```

---

## Task 11: workload-best-practices/disallow-latest-image-tag

**Files:**
- Create: `workload-best-practices/disallow-latest-image-tag/.chainsaw-test/valid-pod.yaml`
- Create: `workload-best-practices/disallow-latest-image-tag/.chainsaw-test/invalid-latest-tag.yaml`
- Create: `workload-best-practices/disallow-latest-image-tag/.chainsaw-test/invalid-no-tag.yaml`
- Create: `workload-best-practices/disallow-latest-image-tag/.chainsaw-test/chainsaw-test.yaml`
- Create: `workload-best-practices/disallow-latest-image-tag/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`workload-best-practices/disallow-latest-image-tag/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
spec:
  containers:
    - name: app
      image: nginx:1.25.3
```

`workload-best-practices/disallow-latest-image-tag/.chainsaw-test/invalid-latest-tag.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-latest-tag
spec:
  containers:
    - name: app
      image: nginx:latest
```

`workload-best-practices/disallow-latest-image-tag/.chainsaw-test/invalid-no-tag.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-no-tag
spec:
  containers:
    - name: app
      image: nginx
```

- [ ] **Step 2: Write the Chainsaw test**

`workload-best-practices/disallow-latest-image-tag/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-latest-image-tag
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with pinned image tag should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod with latest tag should be blocked
      try:
        - apply:
            file: invalid-latest-tag.yaml
            expect:
              - check:
                  ($error != null): true
    - name: 04 - Pod with no tag should be blocked
      try:
        - apply:
            file: invalid-no-tag.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test workload-best-practices/disallow-latest-image-tag
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`workload-best-practices/disallow-latest-image-tag/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-image-tag
  annotations:
    policies.kyverno.io/title: Disallow Latest Image Tag
    policies.kyverno.io/category: Workload Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      The latest image tag is mutable and makes deployments non-deterministic. An image
      tagged latest today may be a different image tomorrow, causing unexpected behavior
      after a node restart or scale event. This policy requires all container images to
      specify an explicit, non-latest tag.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-latest-image-tag
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.containers.all(c,
                  c.image.contains(':') &&
                  !c.image.endsWith(':latest') &&
                  !c.image.endsWith(':')
                ) &&
                (!has(object.spec.initContainers) || object.spec.initContainers.all(c,
                  c.image.contains(':') &&
                  !c.image.endsWith(':latest') &&
                  !c.image.endsWith(':')
                ))
              message: "Container images must specify an explicit, non-latest tag (e.g. nginx:1.25.3 not nginx or nginx:latest)."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test workload-best-practices/disallow-latest-image-tag
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add workload-best-practices/disallow-latest-image-tag/
git commit -m "feat: add disallow-latest-image-tag policy"
```

---

## Task 12: networking/disallow-wildcard-ingress

**Files:**
- Create: `networking/disallow-wildcard-ingress/.chainsaw-test/valid-ingress.yaml`
- Create: `networking/disallow-wildcard-ingress/.chainsaw-test/invalid-wildcard-host.yaml`
- Create: `networking/disallow-wildcard-ingress/.chainsaw-test/chainsaw-test.yaml`
- Create: `networking/disallow-wildcard-ingress/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`networking/disallow-wildcard-ingress/.chainsaw-test/valid-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: valid-ingress
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

`networking/disallow-wildcard-ingress/.chainsaw-test/invalid-wildcard-host.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: invalid-wildcard-host
spec:
  rules:
    - host: "*.example.com"
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

- [ ] **Step 2: Write the Chainsaw test**

`networking/disallow-wildcard-ingress/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-wildcard-ingress
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Ingress with explicit host should be admitted
      try:
        - apply:
            file: valid-ingress.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Ingress with wildcard host should be blocked
      try:
        - apply:
            file: invalid-wildcard-host.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test networking/disallow-wildcard-ingress
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`networking/disallow-wildcard-ingress/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-wildcard-ingress
  annotations:
    policies.kyverno.io/title: Disallow Wildcard Ingress
    policies.kyverno.io/category: Networking
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Ingress
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Wildcard hostnames in Ingress rules (e.g., *.example.com) can be used to intercept
      traffic intended for other services in the cluster. This policy disallows Ingress
      rules whose host contains a wildcard character (*).
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-wildcard-ingress
      match:
        any:
          - resources:
              kinds: [Ingress]
              operations: [CREATE, UPDATE]
      celPreconditions:
        - name: has-rules
          expression: "has(object.spec.rules)"
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.rules.all(rule,
                  !has(rule.host) || !rule.host.contains('*')
                )
              message: "Ingress rules must not use wildcard hostnames. Replace '*.example.com' with an explicit hostname."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test networking/disallow-wildcard-ingress
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add networking/disallow-wildcard-ingress/
git commit -m "feat: add disallow-wildcard-ingress policy"
```

---

## Task 13: networking/disallow-ingress-without-host

**Files:**
- Create: `networking/disallow-ingress-without-host/.chainsaw-test/valid-ingress.yaml`
- Create: `networking/disallow-ingress-without-host/.chainsaw-test/invalid-no-host.yaml`
- Create: `networking/disallow-ingress-without-host/.chainsaw-test/invalid-blank-host.yaml`
- Create: `networking/disallow-ingress-without-host/.chainsaw-test/chainsaw-test.yaml`
- Create: `networking/disallow-ingress-without-host/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`networking/disallow-ingress-without-host/.chainsaw-test/valid-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: valid-ingress
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

`networking/disallow-ingress-without-host/.chainsaw-test/invalid-no-host.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: invalid-no-host
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

`networking/disallow-ingress-without-host/.chainsaw-test/invalid-blank-host.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: invalid-blank-host
spec:
  rules:
    - host: ""
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: app
                port:
                  number: 80
```

- [ ] **Step 2: Write the Chainsaw test**

`networking/disallow-ingress-without-host/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-ingress-without-host
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Ingress with host should be admitted
      try:
        - apply:
            file: valid-ingress.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Ingress without host field should be blocked
      try:
        - apply:
            file: invalid-no-host.yaml
            expect:
              - check:
                  ($error != null): true
    - name: 04 - Ingress with blank host should be blocked
      try:
        - apply:
            file: invalid-blank-host.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test networking/disallow-ingress-without-host
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`networking/disallow-ingress-without-host/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-ingress-without-host
  annotations:
    policies.kyverno.io/title: Disallow Ingress Without Host
    policies.kyverno.io/category: Networking
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Ingress
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Ingress resources without a host match all incoming traffic, potentially
      routing requests intended for other services. This policy requires every
      Ingress rule to specify a non-blank hostname.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-ingress-without-host
      match:
        any:
          - resources:
              kinds: [Ingress]
              operations: [CREATE, UPDATE]
      celPreconditions:
        - name: has-rules
          expression: "has(object.spec.rules)"
      validate:
        cel:
          expressions:
            - expression: >-
                object.spec.rules.all(rule,
                  has(rule.host) && rule.host != ''
                )
              message: "Every Ingress rule must specify a non-blank host. Add a host field to each rule."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test networking/disallow-ingress-without-host
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add networking/disallow-ingress-without-host/
git commit -m "feat: add disallow-ingress-without-host policy"
```

---

## Task 14: networking/disallow-nodeport-services

**Files:**
- Create: `networking/disallow-nodeport-services/.chainsaw-test/valid-service.yaml`
- Create: `networking/disallow-nodeport-services/.chainsaw-test/invalid-nodeport.yaml`
- Create: `networking/disallow-nodeport-services/.chainsaw-test/chainsaw-test.yaml`
- Create: `networking/disallow-nodeport-services/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`networking/disallow-nodeport-services/.chainsaw-test/valid-service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: valid-service
spec:
  selector:
    app: myapp
  ports:
    - port: 80
      targetPort: 8080
```

`networking/disallow-nodeport-services/.chainsaw-test/invalid-nodeport.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: invalid-nodeport
spec:
  type: NodePort
  selector:
    app: myapp
  ports:
    - port: 80
      targetPort: 8080
      nodePort: 30080
```

- [ ] **Step 2: Write the Chainsaw test**

`networking/disallow-nodeport-services/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-nodeport-services
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - ClusterIP service should be admitted
      try:
        - apply:
            file: valid-service.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - NodePort service should be blocked
      try:
        - apply:
            file: invalid-nodeport.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test networking/disallow-nodeport-services
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`networking/disallow-nodeport-services/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-nodeport-services
  annotations:
    policies.kyverno.io/title: Disallow NodePort Services
    policies.kyverno.io/category: Networking
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Service
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      NodePort services expose workloads directly on a static port of every cluster node,
      bypassing ingress controllers and their security policies. This policy disallows
      Services of type NodePort, requiring the use of ClusterIP with an Ingress instead.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-nodeport-services
      match:
        any:
          - resources:
              kinds: [Service]
              operations: [CREATE, UPDATE]
      validate:
        cel:
          expressions:
            - expression: "!has(object.spec.type) || object.spec.type != 'NodePort'"
              message: "Services of type NodePort are not allowed. Use ClusterIP with an Ingress to expose workloads."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test networking/disallow-nodeport-services
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add networking/disallow-nodeport-services/
git commit -m "feat: add disallow-nodeport-services policy"
```

---

## Task 15: rbac/disallow-wildcard-verbs

**Files:**
- Create: `rbac/disallow-wildcard-verbs/.chainsaw-test/valid-clusterrole.yaml`
- Create: `rbac/disallow-wildcard-verbs/.chainsaw-test/invalid-wildcard-verb.yaml`
- Create: `rbac/disallow-wildcard-verbs/.chainsaw-test/invalid-wildcard-resource.yaml`
- Create: `rbac/disallow-wildcard-verbs/.chainsaw-test/chainsaw-test.yaml`
- Create: `rbac/disallow-wildcard-verbs/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`rbac/disallow-wildcard-verbs/.chainsaw-test/valid-clusterrole.yaml`:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-valid-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

`rbac/disallow-wildcard-verbs/.chainsaw-test/invalid-wildcard-verb.yaml`:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-invalid-wildcard-verb
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["*"]
```

`rbac/disallow-wildcard-verbs/.chainsaw-test/invalid-wildcard-resource.yaml`:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: test-invalid-wildcard-resource
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["get", "list"]
```

- [ ] **Step 2: Write the Chainsaw test**

`rbac/disallow-wildcard-verbs/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-wildcard-verbs
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - ClusterRole with explicit verbs and resources should be admitted
      try:
        - apply:
            file: valid-clusterrole.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - ClusterRole with wildcard verb should be blocked
      try:
        - apply:
            file: invalid-wildcard-verb.yaml
            expect:
              - check:
                  ($error != null): true
    - name: 04 - ClusterRole with wildcard resource should be blocked
      try:
        - apply:
            file: invalid-wildcard-resource.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test rbac/disallow-wildcard-verbs
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`rbac/disallow-wildcard-verbs/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-wildcard-verbs
  annotations:
    policies.kyverno.io/title: Disallow Wildcard Verbs and Resources in RBAC
    policies.kyverno.io/category: RBAC
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: ClusterRole, Role
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Using wildcards (*) in RBAC verbs or resources grants overly broad permissions,
      violating the principle of least privilege. This policy disallows ClusterRoles
      and Roles from using * in either verbs or resources fields.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-wildcard-verbs
      match:
        any:
          - resources:
              kinds: [ClusterRole, Role]
              operations: [CREATE, UPDATE]
      validate:
        cel:
          expressions:
            - expression: >-
                !has(object.rules) || object.rules.all(rule,
                  (!has(rule.verbs) || !rule.verbs.exists(v, v == '*')) &&
                  (!has(rule.resources) || !rule.resources.exists(r, r == '*'))
                )
              message: "ClusterRoles and Roles must not use wildcard (*) in verbs or resources. Specify explicit permissions."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test rbac/disallow-wildcard-verbs
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add rbac/disallow-wildcard-verbs/
git commit -m "feat: add disallow-wildcard-verbs policy"
```

---

## Task 16: rbac/disallow-cluster-admin-binding

**Files:**
- Create: `rbac/disallow-cluster-admin-binding/.chainsaw-test/valid-binding.yaml`
- Create: `rbac/disallow-cluster-admin-binding/.chainsaw-test/invalid-cluster-admin-binding.yaml`
- Create: `rbac/disallow-cluster-admin-binding/.chainsaw-test/chainsaw-test.yaml`
- Create: `rbac/disallow-cluster-admin-binding/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`rbac/disallow-cluster-admin-binding/.chainsaw-test/valid-binding.yaml`:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-valid-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
  - kind: ServiceAccount
    name: test-sa
    namespace: default
```

`rbac/disallow-cluster-admin-binding/.chainsaw-test/invalid-cluster-admin-binding.yaml`:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: test-invalid-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: test-sa
    namespace: default
```

- [ ] **Step 2: Write the Chainsaw test**

`rbac/disallow-cluster-admin-binding/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-cluster-admin-binding
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Binding to non-admin role should be admitted
      try:
        - apply:
            file: valid-binding.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Binding to cluster-admin should be blocked
      try:
        - apply:
            file: invalid-cluster-admin-binding.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test rbac/disallow-cluster-admin-binding
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`rbac/disallow-cluster-admin-binding/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-cluster-admin-binding
  annotations:
    policies.kyverno.io/title: Disallow Cluster-Admin ClusterRoleBinding
    policies.kyverno.io/category: RBAC
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: ClusterRoleBinding
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      The cluster-admin ClusterRole grants unrestricted access to every resource in the
      cluster. Binding subjects to cluster-admin bypasses all access controls. This policy
      disallows creating new ClusterRoleBindings that reference the cluster-admin role.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: disallow-cluster-admin-binding
      match:
        any:
          - resources:
              kinds: [ClusterRoleBinding]
              operations: [CREATE, UPDATE]
      validate:
        cel:
          expressions:
            - expression: "object.roleRef.name != 'cluster-admin'"
              message: "Binding to the cluster-admin ClusterRole is not allowed. Use a scoped role with the minimum required permissions."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test rbac/disallow-cluster-admin-binding
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add rbac/disallow-cluster-admin-binding/
git commit -m "feat: add disallow-cluster-admin-binding policy"
```

---

## Task 17: labels/require-standard-labels

**Files:**
- Create: `labels/require-standard-labels/.chainsaw-test/valid-pod.yaml`
- Create: `labels/require-standard-labels/.chainsaw-test/invalid-no-labels.yaml`
- Create: `labels/require-standard-labels/.chainsaw-test/invalid-missing-version.yaml`
- Create: `labels/require-standard-labels/.chainsaw-test/chainsaw-test.yaml`
- Create: `labels/require-standard-labels/policy.yaml`

- [ ] **Step 1: Write test fixtures**

`labels/require-standard-labels/.chainsaw-test/valid-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: valid-pod
  labels:
    app.kubernetes.io/name: myapp
    app.kubernetes.io/version: "1.0.0"
spec:
  containers:
    - name: app
      image: nginx:1.25
```

`labels/require-standard-labels/.chainsaw-test/invalid-no-labels.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-no-labels
spec:
  containers:
    - name: app
      image: nginx:1.25
```

`labels/require-standard-labels/.chainsaw-test/invalid-missing-version.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: invalid-missing-version
  labels:
    app.kubernetes.io/name: myapp
spec:
  containers:
    - name: app
      image: nginx:1.25
```

- [ ] **Step 2: Write the Chainsaw test**

`labels/require-standard-labels/.chainsaw-test/chainsaw-test.yaml`:
```yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: require-standard-labels
spec:
  steps:
    - name: 01 - Apply policy
      try:
        - apply:
            file: ../policy.yaml
    - name: 02 - Pod with required labels should be admitted
      try:
        - apply:
            file: valid-pod.yaml
            expect:
              - check:
                  ($error == null): true
    - name: 03 - Pod without any labels should be blocked
      try:
        - apply:
            file: invalid-no-labels.yaml
            expect:
              - check:
                  ($error != null): true
    - name: 04 - Pod missing app.kubernetes.io/version should be blocked
      try:
        - apply:
            file: invalid-missing-version.yaml
            expect:
              - check:
                  ($error != null): true
```

- [ ] **Step 3: Run the test — expect failure (policy.yaml missing)**

```bash
chainsaw test labels/require-standard-labels
# Expected: FAIL — ../policy.yaml not found
```

- [ ] **Step 4: Write the policy**

`labels/require-standard-labels/policy.yaml`:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-standard-labels
  annotations:
    policies.kyverno.io/title: Require Standard Kubernetes Labels
    policies.kyverno.io/category: Labels
    policies.kyverno.io/severity: low
    policies.kyverno.io/subject: Pod
    kyverno.io/kyverno-version: "1.16.2"
    kyverno.io/kubernetes-version: "1.34"
    policies.kyverno.io/description: >-
      Standard Kubernetes labels (app.kubernetes.io/name and app.kubernetes.io/version)
      enable consistent tooling, dashboards, and policy targeting across the cluster.
      This policy requires all pods to carry both labels with non-empty values.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: require-standard-labels
      match:
        any:
          - resources:
              kinds: [Pod]
              operations: [CREATE, UPDATE]
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kyverno]
      validate:
        cel:
          expressions:
            - expression: >-
                has(object.metadata.labels) &&
                'app.kubernetes.io/name' in object.metadata.labels &&
                object.metadata.labels['app.kubernetes.io/name'] != '' &&
                'app.kubernetes.io/version' in object.metadata.labels &&
                object.metadata.labels['app.kubernetes.io/version'] != ''
              message: "Pods must have 'app.kubernetes.io/name' and 'app.kubernetes.io/version' labels set to non-empty values."
```

- [ ] **Step 5: Run the test — expect pass**

```bash
chainsaw test labels/require-standard-labels
# Expected: PASS
```

- [ ] **Step 6: Commit**

```bash
git add labels/require-standard-labels/
git commit -m "feat: add require-standard-labels policy"
```

---

## Final Verification

- [ ] **Run all tests**

```bash
chainsaw test
# Expected: PASS — all 15 policies pass their tests
```

- [ ] **Verify policy count**

```bash
find . -name "policy.yaml" | sort
# Expected: 15 files, one per policy
```
