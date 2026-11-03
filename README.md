# CCAI Platform Geo-Enrichment & Security Layer

A serverless middleware reference solution designed to enrich the **Google Contact Center AI Platform (CCaaS) Web SDK v3** with real-time geographic metadata and security risk assessments.

By identifying a client's IP address, geolocation, ISP, and network privacy status (VPN/Datacenter/Hosting) before a session is initialized, organizations can automate intelligent routing, prevent fraudulent interactions, enforce IP/country blocklists, and deliver localized customer experiences.

The architecture supports **Multi-Token Merging**, allowing applications to pass existing CRM/application context (e.g., loyalty tiers, account status) signed with a dedicated upstream key (`APP_TOKEN_SECRET`) into the service, where it is cryptographically verified and merged with live geo-security data into a single CCaaS JSON Web Token (JWT) signed with `COMPANY_SECRET` (`HS256`).

---

## Project Structure

```text
/
├── public/                 # Static assets served only when Demo Mode is enabled
│   ├── index.html          # Demo harness HTML
│   ├── demo.css            # External stylesheet for strict CSP compliance
│   └── demo.js             # Demo Web SDK v3 flow (uses demo-only /auth/token stub)
├── index.js                # Core backend service (Express / Helmet / JWT / Firestore)
├── cloudbuild.yaml         # Multi-region CI/CD deployment pipeline
├── Dockerfile              # Multi-stage build (Node 20 build -> Distroless nonroot runtime)
├── .dockerignore           # Excludes local artifacts, git metadata, and docs from build context
├── package.json            # Node.js dependencies and start scripts
├── package-lock.json       # Locked dependency tree for deterministic npm ci builds
├── CONTRIBUTING.md         # Contributor License Agreement & guidelines
└── LICENSE                 # Apache 2.0 License
```

---

## Solution Architecture

All client metadata is evaluated server-side and cryptographically signed before being passed to the CCaaS Web SDK:

1. **Frontend Request:** The browser client calls the Global External Application Load Balancer (`POST /generate-chat-token`).
2. **Edge Protection (Primary Control):** Google Cloud Armor enforces edge IP/geo rules, WAF policies, and rate limits before traffic reaches Cloud Run. Cloud Run is deployed with `--ingress=internal-and-cloud-load-balancing` so requests cannot bypass the Load Balancer and Cloud Armor via the `*.run.app` URL.
3. **Trusted Client IP Extraction:** The Express service configures an explicit proxy hop count (`TRUST_PROXY_HOPS`, defaulting to `1` for the External Application Load Balancer) and validates `req.ip` with `net.isIP()` so client-supplied `X-Forwarded-For` headers cannot spoof the client IP.
4. **Verification & Enrichment:** If an upstream application JWT is provided, the service verifies its `HS256` signature, issuer (`APP_TOKEN_ISSUER`), audience (`APP_TOKEN_AUDIENCE`), and max age (`15m`) using `APP_TOKEN_SECRET` (kept strictly separate from `COMPANY_SECRET`), fetches live Geo-IP and privacy intelligence from IPinfo.io using an `Authorization: Bearer` header, and queries Cloud Firestore (`ccaas-ip-check`) for blocklist matches.
5. **Fail-Closed Enforcement & Signing:** If either enforcement mode is `HARD_BLOCK` and the Firestore lookup fails, the service fails closed with `HTTP 503`. Otherwise, a consolidated JWT signed with `COMPANY_SECRET` (`HS256`) is returned to initialize the CCaaS Web SDK.

### Security Enforcement Modes

| Setting | Match Result | User Experience |
| :--- | :--- | :--- |
| `HARD_BLOCK` | Service returns `403 Forbidden` (or `503` if lookup is unavailable) | Chat widget fails to mount; user is blocked at initialization. |
| `PASS_THROUGH` | `is_ip_blocked` / `is_country_blocked` set to `"true"` in JWT | Chat mounts; Virtual Agent / Routing Rules route session to a dedicated Security Queue. |

---

## Google Cloud Configuration Guide

### 1. Enable Required APIs

```bash
gcloud services enable \
    run.googleapis.com \
    firestore.googleapis.com \
    secretmanager.googleapis.com \
    compute.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com
```

### 2. Configure Named Firestore Database (`ccaas-ip-check`)

1. **Create Database Instance:**
   ```bash
   gcloud firestore databases create \
       --database=ccaas-ip-check \
       --location=[REGION] \
       --type=firestore-native
   ```
2. **Initialize Configuration Document:**
   Create a collection named `app_config` with a document named `settings` containing:
   * `ip_enforcement_mode`: `"PASS_THROUGH"` or `"HARD_BLOCK"`
   * `country_enforcement_mode`: `"PASS_THROUGH"` or `"HARD_BLOCK"`
3. **Create Blocklists:**
   * `blocklist_ips`: Document IDs match blocked IP addresses.
   * `blocklist_countries`: Document IDs match ISO 3166-1 alpha-2 country codes (e.g., `"RU"`, `"CN"`).

### 3. Configure Secret Manager

Store the following secrets in Google Cloud Secret Manager:
* `ccaas-company-secret` (`COMPANY_SECRET`): CCaaS Shared Secret used exclusively to sign outbound tokens for CCaaS (`HS256`).
* `ccaas-app-token-secret` (`APP_TOKEN_SECRET`): Separate shared secret used exclusively to verify inbound upstream application context tokens (`HS256`). Must be distinct from `COMPANY_SECRET`.
* `ccaas-company-id` (`COMPANY_ID`): CCaaS Company ID.
* `ccaas-host` (`CCAAS_HOST`): CCaaS Tenant Host (e.g., `tenant.ccaiplatform.com`).
* `ipinfo-api-token` (`IPINFO_TOKEN`): API Token from [IPinfo.io](https://ipinfo.io/).

### 4. Provision a Dedicated Least-Privilege Service Account

Do **not** use the default Compute Engine service account (`[PROJECT_NUMBER]-compute@developer.gserviceaccount.com`). Create a dedicated service account and grant only the required permissions:

```bash
export PROJECT_ID=$(gcloud config get-value project)

gcloud iam service-accounts create ccaas-token-service \
    --display-name="CCaaS Geo-Enrichment Token Service"

# Grant Firestore access
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:ccaas-token-service@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/datastore.user"

# Grant Secret Manager access scoped to the required secrets only
for SECRET in ccaas-company-secret ccaas-app-token-secret ccaas-company-id ccaas-host ipinfo-api-token; do
  gcloud secrets add-iam-policy-binding "$SECRET" \
      --member="serviceAccount:ccaas-token-service@${PROJECT_ID}.iam.gserviceaccount.com" \
      --role="roles/secretmanager.secretAccessor"
done
```

---

## Deployment & Configuration

Configure `_ALLOWED_ORIGINS` (comma-separated list of trusted `https://` frontend origins) and `_TRUST_PROXY_HOPS` in `cloudbuild.yaml`, then deploy across regions using Cloud Build:

```bash
gcloud builds submit --config cloudbuild.yaml \
    --substitutions=_ALLOWED_ORIGINS="https://support.example.com" .
```

> **Note on Demo Mode & Identity Authentication (`/auth/token`):**
> `_SERVE_DEMO` and `_DEBUG_PAYLOAD` default to `'false'` in `cloudbuild.yaml`.
> The `/auth/token` and `/demo/init-token` endpoints are mounted **only** when `SERVE_DEMO=true` for local/demo testing, and the server refuses to start with `SERVE_DEMO=true` on Cloud Run (`K_SERVICE`) unless `DEMO_ACK_INSECURE=true` is explicitly set.
> **Before go-live**, the Web SDK v3 `authenticate` callback in your frontend must call your own authenticated backend service (which verifies the logged-in user's session before minting an identity JWT) rather than the demo `/auth/token` stub.

---

## Disclaimer

This is not an officially supported Google product. This project is not eligible for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

## License

Copyright 2026 Google LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
