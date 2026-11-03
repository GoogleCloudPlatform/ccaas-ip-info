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

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { Firestore } from '@google-cloud/firestore';
import fs from 'fs';
import net from 'net';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 8080;

// Environment Variables from Secret Manager and Cloud Build
const COMPANY_SECRET = process.env.COMPANY_SECRET;
const APP_TOKEN_SECRET = process.env.APP_TOKEN_SECRET;
const APP_TOKEN_ISSUER = process.env.APP_TOKEN_ISSUER || 'ccaas-upstream-app';
const APP_TOKEN_AUDIENCE = process.env.APP_TOKEN_AUDIENCE || 'ccaas-enrichment-service';
const COMPANY_ID = process.env.COMPANY_ID;
const CCAAS_HOST = process.env.CCAAS_HOST;
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;
const USE_IPINFO = process.env.USE_IPINFO === 'true';
const DEBUG_PAYLOAD = process.env.DEBUG_PAYLOAD === 'true';
const SERVE_DEMO = process.env.SERVE_DEMO === 'true';
const DEMO_ACK_INSECURE = process.env.DEMO_ACK_INSECURE === 'true';
const DEFAULT_ENFORCEMENT_MODE = process.env.DEFAULT_ENFORCEMENT_MODE || 'HARD_BLOCK';

// Guard against accidentally enabling Demo Mode on Cloud Run without explicit acknowledgment
if (SERVE_DEMO && process.env.K_SERVICE && !DEMO_ACK_INSECURE) {
  console.error(
    'FATAL: SERVE_DEMO=true is not permitted on Cloud Run unless DEMO_ACK_INSECURE=true is explicitly set. ' +
      'Disable SERVE_DEMO in production or protect the demo service with Cloud Run IAM.'
  );
  process.exit(1);
}

/**
 * INITIALIZATION & MIDDLEWARE HARDENING
 */
const db = new Firestore({
  databaseId: process.env.DATABASE_ID || 'ccaas-ip-check'
});

// Configure explicit proxy hop count (e.g., 1 hop for Global External Application Load Balancer)
// instead of `true` so client-supplied X-Forwarded-For entries cannot spoof req.ip.
const parsedHops = Number.parseInt(process.env.TRUST_PROXY_HOPS || '1', 10);
const TRUST_PROXY_HOPS = Number.isNaN(parsedHops) || parsedHops < 0 ? 1 : parsedHops;
app.set('trust proxy', TRUST_PROXY_HOPS);

// Standard HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options)
const trustedCcaasOrigin =
  CCAAS_HOST && /^[a-zA-Z0-9.-]+$/.test(CCAAS_HOST) ? `https://${CCAAS_HOST}` : null;
const trustedCcaasWsOrigin =
  CCAAS_HOST && /^[a-zA-Z0-9.-]+$/.test(CCAAS_HOST) ? `wss://${CCAAS_HOST}` : null;

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", ...(trustedCcaasOrigin ? [trustedCcaasOrigin] : [])],
        styleSrc: ["'self'"],
        connectSrc: [
          "'self'",
          ...(trustedCcaasOrigin ? [trustedCcaasOrigin] : []),
          ...(trustedCcaasWsOrigin ? [trustedCcaasWsOrigin] : [])
        ],
        frameSrc: ["'self'", ...(trustedCcaasOrigin ? [trustedCcaasOrigin] : [])],
        imgSrc: ["'self'", 'data:', ...(trustedCcaasOrigin ? [trustedCcaasOrigin] : [])],
        objectSrc: ["'none'"]
      }
    }
  })
);

// Strict CORS origin allowlist (HTTPS required; localhost HTTP allowed only in local Demo Mode)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(
    (o) =>
      o.startsWith('https://') ||
      (SERVE_DEMO && (o.startsWith('http://localhost:') || o === 'http://localhost'))
  );

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    methods: ['POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600
  })
);

app.use(express.json({ limit: '16kb' }));

/**
 * INPUT VALIDATION HELPERS
 */
function normalizeAndValidateIp(rawIp) {
  if (typeof rawIp !== 'string') return null;
  const trimmed = rawIp.trim().replace(/^::ffff:/i, '');
  return net.isIP(trimmed) !== 0 ? trimmed : null;
}

function isValidCountryCode(code) {
  return typeof code === 'string' && /^[A-Z]{2}$/.test(code);
}

let lastKnownIpMode = DEFAULT_ENFORCEMENT_MODE;
let lastKnownCountryMode = DEFAULT_ENFORCEMENT_MODE;

/**
 * SECURITY EVALUATOR
 */
async function evaluateSecurity(ip, countryCode) {
  try {
    if (!ip || net.isIP(ip) === 0) {
      throw new Error('Invalid client IP address');
    }

    const [ipDoc, countryDoc, configDoc] = await Promise.all([
      db.collection('blocklist_ips').doc(ip).get(),
      isValidCountryCode(countryCode)
        ? db.collection('blocklist_countries').doc(countryCode).get()
        : Promise.resolve({ exists: false }),
      db.collection('app_config').doc('settings').get()
    ]);

    const config = configDoc.exists ? configDoc.data() : {};
    const ipMode = config.ip_enforcement_mode || DEFAULT_ENFORCEMENT_MODE;
    const countryMode = config.country_enforcement_mode || DEFAULT_ENFORCEMENT_MODE;
    lastKnownIpMode = ipMode;
    lastKnownCountryMode = countryMode;

    const results = {
      ipBlocked: ipDoc.exists,
      countryBlocked: Boolean(countryDoc.exists),
      shouldHardBlock: false,
      evaluationError: false,
      reason: null
    };

    if (results.ipBlocked && ipMode === 'HARD_BLOCK') {
      results.shouldHardBlock = true;
      results.reason = 'IP_HARD_BLOCK';
    }

    if (results.countryBlocked && !results.shouldHardBlock && countryMode === 'HARD_BLOCK') {
      results.shouldHardBlock = true;
      results.reason = 'COUNTRY_HARD_BLOCK';
    }

    return results;
  } catch (error) {
    console.error('Security Evaluation Error:', error);
    const failClosed =
      lastKnownIpMode === 'HARD_BLOCK' || lastKnownCountryMode === 'HARD_BLOCK';
    return {
      ipBlocked: false,
      countryBlocked: false,
      shouldHardBlock: failClosed,
      evaluationError: true,
      reason: 'SECURITY_EVALUATION_ERROR'
    };
  }
}

/**
 * DEMO-ONLY HANDLER: Identity Authentication (/auth/token)
 *
 * IMPORTANT (PRE-GO-LIVE REQUIREMENT):
 * This endpoint is retained strictly for Demo Mode (`SERVE_DEMO=true`) so the
 * local/demo harness can satisfy the CCAI Platform Web SDK v3 `authenticate`
 * callback without an external identity provider.
 *
 * THIS WILL BE CHANGED BEFORE GO-LIVE:
 * In production deployments (`SERVE_DEMO=false`, the default), this endpoint is
 * disabled and not mounted. Before go-live, the Web SDK `authenticate` callback
 * must point to the customer's own authenticated backend service, which verifies
 * the logged-in user's session before signing identity claims.
 */
const authHandler = (req, res) => {
  if (!SERVE_DEMO) return res.status(404).json({ error: 'Not found' });
  try {
    const rawPayload =
      req.body && typeof req.body.payload === 'object' && req.body.payload !== null
        ? req.body.payload
        : {};
    const iat = Math.floor(Date.now() / 1000) - 5;
    const payload = {
      identifier: String(rawPayload.identifier || 'demo-user@example.com'),
      name: String(rawPayload.name || 'Demo User'),
      iss: CCAAS_HOST,
      iat,
      exp: iat + 600
    };

    const token = jwt.sign(payload, COMPANY_SECRET, { algorithm: 'HS256' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Auth failed' });
  }
};

/**
 * HANDLER: Custom Data Enrichment & Merging (POST /generate-chat-token)
 */
const tokenHandler = async (req, res) => {
  try {
    const clientIp = normalizeAndValidateIp(req.ip);
    let countryCode = 'Unknown';
    let ipData = {};
    let mergedData = {};

    // 1. Optional: Extract and Verify incoming upstream application token
    // Verified strictly with APP_TOKEN_SECRET (must be distinct from COMPANY_SECRET)
    if (req.body && req.body.token) {
      if (!APP_TOKEN_SECRET || APP_TOKEN_SECRET === COMPANY_SECRET) {
        console.error(
          'APP_TOKEN_SECRET must be configured and distinct from COMPANY_SECRET to verify upstream tokens.'
        );
        return res.status(500).json({ error: 'Upstream token verification misconfigured' });
      }
      try {
        const verified = jwt.verify(req.body.token, APP_TOKEN_SECRET, {
          algorithms: ['HS256'],
          issuer: APP_TOKEN_ISSUER,
          audience: APP_TOKEN_AUDIENCE,
          maxAge: '15m'
        });
        if (
          verified &&
          typeof verified === 'object' &&
          verified.custom_data &&
          typeof verified.custom_data === 'object' &&
          !Array.isArray(verified.custom_data)
        ) {
          mergedData = { ...verified.custom_data };
        }
      } catch (e) {
        console.warn('Incoming token verification failed:', e.message);
        return res.status(401).json({ error: 'Invalid upstream token' });
      }
    }

    // 2. Fetch Geo-Enrichment using validated IP and Authorization header
    if (USE_IPINFO && clientIp && IPINFO_TOKEN) {
      try {
        const response = await fetch(
          `https://ipinfo.io/${encodeURIComponent(clientIp)}/json`,
          {
            headers: {
              Authorization: `Bearer ${IPINFO_TOKEN}`,
              Accept: 'application/json'
            }
          }
        );
        if (response.ok) {
          ipData = await response.json();
          countryCode = isValidCountryCode(ipData.country) ? ipData.country : 'Unknown';
        }
      } catch (e) {
        console.error('IPinfo error:', e);
      }
    }

    // 3. Evaluate Security (fails closed with HTTP 503 if HARD_BLOCK evaluation errors)
    const security = await evaluateSecurity(clientIp, countryCode);
    if (security.evaluationError && security.shouldHardBlock) {
      return res.status(503).json({ error: 'Security evaluation unavailable' });
    }
    if (security.shouldHardBlock) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // 4. Helper to merge data into nested object structure (overwrites any colliding keys)
    const addData = (id, label, value) => {
      if (value !== undefined && value !== null) {
        mergedData[id] = { label, value: String(value) };
      }
    };

    addData('client_ip', 'Client IP', clientIp || 'Unknown');
    addData('client_country', 'Country', countryCode);
    addData('is_ip_blocked', 'IP Blocked', security.ipBlocked);
    addData('is_country_blocked', 'Country Blocked', security.countryBlocked);

    if (ipData.city) addData('client_city', 'City', ipData.city);
    if (ipData.org) addData('client_isp', 'ISP', ipData.org);
    addData('client_vpn', 'Using VPN', Boolean(ipData.privacy?.vpn));
    addData('client_hosting', 'Datacenter', Boolean(ipData.privacy?.hosting));

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      custom_data: mergedData,
      iss: CCAAS_HOST,
      iat: now - 5,
      exp: now + 3600
    };

    const token = jwt.sign(payload, COMPANY_SECRET, { algorithm: 'HS256' });
    res.status(200).json({ token, ...(DEBUG_PAYLOAD && { debug_payload: payload }) });
  } catch (error) {
    res.status(500).json({ error: 'Token generation failed' });
  }
};

/**
 * DEMO ONLY ENDPOINT: Initial App Token Signing (/demo/init-token)
 * Signs simulated upstream CRM context using APP_TOKEN_SECRET (never COMPANY_SECRET).
 */
const demoInitHandler = (req, res) => {
  if (!SERVE_DEMO) return res.status(404).send();
  try {
    if (!APP_TOKEN_SECRET || APP_TOKEN_SECRET === COMPANY_SECRET) {
      return res
        .status(500)
        .json({ error: 'APP_TOKEN_SECRET must be set and distinct from COMPANY_SECRET' });
    }
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      custom_data:
        req.body && typeof req.body.payload === 'object' && req.body.payload !== null
          ? req.body.payload
          : {},
      iss: APP_TOKEN_ISSUER,
      aud: APP_TOKEN_AUDIENCE,
      iat: now - 5,
      exp: now + 300
    };
    const token = jwt.sign(payload, APP_TOKEN_SECRET, { algorithm: 'HS256' });
    res.status(200).json({ token });
  } catch (e) {
    res.status(500).json({ error: 'Demo init failed' });
  }
};

/**
 * ROUTES & STATIC SERVING
 */
if (SERVE_DEMO) {
  console.warn(
    'WARNING: Demo service enabled (SERVE_DEMO=true). /auth/token and /demo/init-token are active for demo testing only and must be disabled before go-live.'
  );

  app.get('/', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) return res.status(500).send('Demo Error');
      const html = data
        .replace('{{COMPANY_ID}}', COMPANY_ID || '')
        .replace('{{CCAAS_HOST}}', CCAAS_HOST || '');
      res.send(html);
    });
  });

  // NOTE: /auth/token is mounted ONLY in Demo Mode and will be changed/replaced
  // before go-live by the customer's authenticated identity backend.
  app.post('/auth/token', authHandler);
  app.post('/demo/init-token', demoInitHandler);
  app.use(express.static(path.join(__dirname, 'public')));
} else {
  console.log('Demo service disabled');
}

app.post('/generate-chat-token', tokenHandler);

app.listen(PORT, () => console.log(`Service listening on ${PORT}`));
