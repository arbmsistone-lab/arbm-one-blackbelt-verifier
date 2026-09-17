# ARBM ONE Black Belt Public Verifier

This repository contains **no plaintext ARBM ONE source code**.

It stores an AES-256-GCM encrypted exact-SHA snapshot of the private canonical repository and executes the ARBM provider-scope gate on a standard GitHub-hosted public runner.

- Source repository: private `arbmsistone-lab/ARBM-one`
- Source SHA: `517f59707504bee3877075a39419753109e8e641`
- Contract: `ARBM_ONE_CLOUD_CRITICAL_V1`
- Cost policy: ZERO_SPEND

The decryption key is stored only in GitHub Actions Secrets.
