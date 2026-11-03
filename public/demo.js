/**
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Injected by the Node.js demo route onto the <body> data-* attributes
const COMPANY_ID = document.body.dataset.companyId || '';
const CCAAS_HOST = document.body.dataset.ccaasHost || '';
const API_BASE = window.location.origin;

let ccaas;

/**
 * DEMO MODE ONLY — Identity Authentication Callback (v3 SDK Requirement)
 *
 * IMPORTANT (PRE-GO-LIVE REQUIREMENT):
 * This callback calls `/auth/token`, which is enabled ONLY in Demo Mode
 * (`SERVE_DEMO=true`) to simulate identity token generation locally.
 * Before go-live, this callback WILL BE CHANGED to call your application's
 * own authenticated backend endpoint (which verifies the logged-in user's
 * session before minting a signed CCaaS identity JWT).
 */
async function getAuthToken() {
  const res = await fetch(`${API_BASE}/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      payload: {
        identifier: 'demo-user@example.com',
        name: 'Demo User'
      }
    })
  });
  if (!res.ok) {
    throw new Error('Failed to fetch demo auth token');
  }
  return res.json();
}

/**
 * Main Initialization Flow
 */
async function runEnrichedFlow() {
  const btn = document.getElementById('btn-launch');
  const status = document.getElementById('status-msg');
  const debug = document.getElementById('debug-view');
  const debugContainer = document.getElementById('debug-container');

  btn.disabled = true;
  status.textContent = 'Processing enrichment...';
  status.className = 'status-msg';

  try {
    // 1. Get initial demo app token (signs the textarea JSON with APP_TOKEN_SECRET)
    const appData = JSON.parse(document.getElementById('app-data-input').value);
    const initRes = await fetch(`${API_BASE}/demo/init-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload: appData })
    });
    if (!initRes.ok) {
      throw new Error('Demo token initialization failed.');
    }
    const { token: initialToken } = await initRes.json();

    // 2. Fetch Merged Token (Geo + Security + App Data)
    const enrichRes = await fetch(`${API_BASE}/generate-chat-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: initialToken })
    });

    if (enrichRes.status === 403) {
      throw new Error('Access Denied: IP or Country is Blocked.');
    }
    if (!enrichRes.ok) {
      throw new Error(`Enrichment request failed (HTTP ${enrichRes.status}).`);
    }

    const data = await enrichRes.json();

    // 3. Update Debug View
    if (data.debug_payload) {
      debugContainer.classList.remove('hidden');
      debug.textContent = JSON.stringify(data.debug_payload, null, 2);
    }

    // 4. Initialize CCaaS v3 SDK
    ccaas = new window.UJET({
      companyId: COMPANY_ID,
      host: `https://${CCAAS_HOST}`,
      authenticate: getAuthToken
    });

    // 5. Configure with the Merged Enrichment Token
    ccaas.config({ customData: data.token });

    // 6. Mount the widget
    ccaas.mount('#ccaas-widget');

    status.textContent = 'Chat Mounted Successfully';
    status.className = 'status-msg status-success';
  } catch (e) {
    console.error(e);
    status.textContent = 'Initialization Error: ' + e.message;
    status.className = 'status-msg status-error';
    btn.disabled = false;
  }
}

document.getElementById('btn-launch')?.addEventListener('click', runEnrichedFlow);

// Dynamic SDK script loading (only when CCAAS_HOST matches a valid hostname)
if (/^[a-zA-Z0-9.-]+$/.test(CCAAS_HOST)) {
  const script = document.createElement('script');
  script.src = `https://${CCAAS_HOST}/web-sdk/v3/widget.js`;
  document.head.appendChild(script);
}
