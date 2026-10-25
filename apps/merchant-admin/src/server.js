import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto'; // 🔥 Added for Merchant Key Generation
import { getDatabase, MerchantRepository, SupportTicketRepository } from '@youpi/db';
import { getAdminToken, safeEqual } from '@youpi/common';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Security headers applied to every response served by the merchant admin. */
const BASE_SECURITY_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'"
});

/** True when the caller presented the admin bearer token in constant time (or ?token= on GET SSE). */
function hasAdminToken(req, url = null, pathname = '') {
  const match = /^Bearer\s+(.+)$/i.exec(req.headers?.['authorization'] || '');
  if (match) {
    return safeEqual(match[1].trim(), getAdminToken());
  }
  return false;
}

/**
 * Strips headers a browser must not be able to spoof when relaying to an internal service.
 */
function sanitizedForwardHeaders(req, targetHost) {
  const headers = { ...req.headers, host: targetHost };
  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase();
    if (lower === 'x-internal-render' || lower === 'x-internal-token') {
      delete headers[name];
    }
  }
  return headers;
}

// In production, reliably ensure environment variables from .env are loaded if not already provided
if (!process.env.BASE_PAYMENT_API_URL && typeof process.loadEnvFile === 'function') {
  try {
    const rootEnv = path.resolve(__dirname, '../../../.env');
    if (fs.existsSync(rootEnv)) {
      process.loadEnvFile(rootEnv);
    }
  } catch {}
}

export class AdminServer {
  /**
   * @param {{
   *   db?: import('@youpi/db').Database,
   *   apiBaseUrl?: string
   * }} options
   */
  constructor(options = {}) {
    this.db = options.db || getDatabase();
    this.apiBaseUrl = options.apiBaseUrl || process.env.BASE_PAYMENT_API_URL || 'http://localhost:6100';
    this.merchantRepo = new MerchantRepository(this.db);
    this.ticketRepo = new SupportTicketRepository(this.db);
    this.htmlTemplatePath = path.join(__dirname, 'views', 'admin.html');
    this.template = fs.readFileSync(this.htmlTemplatePath, 'utf8');
  }

  renderHtml() {
    try {
      this.template = fs.readFileSync(this.htmlTemplatePath, 'utf8');
    } catch {}

    let html = this.template;
    const clientApiBase = '';
    html = html.replaceAll('{{API_BASE_URL}}', clientApiBase);
    return html;
  }

  createServer() {
    return http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const pathname = url.pathname;

      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        });
        res.end();
        return;
      }

      // Health
      if (pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'UP', service: 'merchant-admin' }));
        return;
      }

      // 🔥 NAYA ROUTE: Create Merchant API & Auto-Generate Keys
      if (pathname === '/api/admin/create-merchant' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
          try {
            const data = new URLSearchParams(body);
            const business_name = data.get('business_name') || 'New Merchant';
            const contact_email = data.get('contact_email') || 'admin@domain.com';
            const contact_phone = data.get('contact_phone') || '9999999999';
            const webhook_url = data.get('webhook_url') || '';

            const merchantId = crypto.randomUUID();
            const webhookSecret = crypto.randomBytes(32).toString('hex');
            const slug = business_name.toLowerCase().replace(/[^a-z0-9]/g, '-') + '-' + Date.now();
            const branding = JSON.stringify({ primaryColor: "#2563eb", appName: business_name, logoUrl: null });

            const sqlBase = `INSERT INTO merchants (id, business_name, slug, contact_email, contact_phone, webhook_url, webhook_secret, branding) VALUES `;
            const params = [merchantId, business_name, slug, contact_email, contact_phone, webhook_url, webhookSecret, branding];

            // Universal DB Engine Support (SQLite, Postgres, etc.)
            if (typeof this.db.query === 'function') {
                try {
                    await this.db.query(sqlBase + `($1, $2, $3, $4, $5, $6, $7, $8)`, params);
                } catch(err) {
                    await this.db.query(sqlBase + `(?, ?, ?, ?, ?, ?, ?, ?)`, params);
                }
            } else if (typeof this.db.run === 'function') {
                await this.db.run(sqlBase + `(?, ?, ?, ?, ?, ?, ?, ?)`, params);
            } else if (typeof this.db.execute === 'function') {
                await this.db.execute(sqlBase + `(?, ?, ?, ?, ?, ?, ?, ?)`, params);
            } else {
                this.merchantRepo.create({ id: merchantId, business_name, slug, contact_email, contact_phone, webhook_url, webhook_secret: webhookSecret });
            }

            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(`
              <div style="font-family: sans-serif; padding: 40px; max-width: 600px; margin: 40px auto; border: 1px solid #cbd5e1; border-radius: 12px; background: #f8fafc; box-shadow: 0 10px 25px rgba(0,0,0,0.1);">
                <h2 style="color: #059669; margin-top: 0;">✅ Merchant Created Successfully!</h2>
                <p><b>Business Name:</b> ${escapeHtml(business_name)}</p>
                <div style="background: #ffffff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; margin: 20px 0;">
                  <p style="margin-top:0;"><b>Merchant ID:</b> <br><code style="color: #0284c7; font-size: 16px; word-break: break-all;">${merchantId}</code></p>
                  <p style="margin-bottom:0;"><b>Webhook Secret (API Key):</b> <br><code style="color: #0284c7; font-size: 16px; word-break: break-all;">${webhookSecret}</code></p>
                </div>
                <p style="color: #64748b; font-size: 14px;"><i>Copy these credentials and paste them into your CodeIgniter (PHP) Backend settings!</i></p>
                <br>
                <a href="/admin" style="display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">⬅ Go Back to Admin Dashboard</a>
              </div>
            `);
          } catch (error) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Database Error: ' + error.message);
          }
        });
        return;
      }
      // 🔥 ROUTE KHATAM

      // Admin Tickets API: GET /api/admin/tickets
      if (pathname === '/api/admin/tickets') {
        if (!hasAdminToken(req)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized', code: 'AUTH_REQUIRED' }));
          return;
        }
        const merchants = this.merchantRepo.findAll();
        const mId = merchants[0]?.id || '00000000-0000-0000-0000-000000000001';
        const tickets = this.ticketRepo.findTicketsByMerchant(mId);

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          ...BASE_SECURITY_HEADERS
        });
        res.end(JSON.stringify(tickets));
        return;
      }

      // Merged Control Center Supervisor Proxy: /api/services/* and /api/logs/stream -> Control Center on port 8090
      if (pathname.startsWith('/api/services') || pathname === '/api/logs/stream') {
        if (!hasAdminToken(req, url, pathname)) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Unauthorized', code: 'AUTH_REQUIRED' }));
          return;
        }
        const ccPort = Number(process.env.CONTROL_CENTER_PORT || 8090);
        const forwardHeaders = sanitizedForwardHeaders(req, `localhost:${ccPort}`);
        if (!forwardHeaders.authorization && !forwardHeaders.Authorization) {
          forwardHeaders.Authorization = `Bearer ${getAdminToken()}`;
        }
        const proxyReq = http.request({
          hostname: '127.0.0.1',
          port: ccPort,
          path: req.url,
          method: req.method,
          headers: forwardHeaders
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Control center supervisor unavailable', details: err.message }));
          }
        });

        req.on('data', chunk => proxyReq.write(chunk));
        req.on('end', () => proxyReq.end());
        return;
      }

      // Transparent API Proxy: /api/* -> Payment Core REST API
      if (pathname.startsWith('/api/')) {
        const targetPort = Number(process.env.PAYMENT_API_PORT || 6100);
        const defaultMerchant = this.merchantRepo.getDefault ? this.merchantRepo.getDefault() : (this.merchantRepo.findById('00000000-0000-0000-0000-000000000001') || this.merchantRepo.findAll()[0]);
        const defaultMerchantId = defaultMerchant?.id || '00000000-0000-0000-0000-000000000001';
        const proxyReq = http.request({
          hostname: '127.0.0.1',
          port: targetPort,
          path: req.url,
          method: req.method,
          headers: {
            ...sanitizedForwardHeaders(req, `localhost:${targetPort}`),
            'x-merchant-id': req.headers['x-merchant-id'] || defaultMerchantId,
            'x-forwarded-host': req.headers.host || '',
            'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'http'
          }
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Gateway API unavailable', details: err.message }));
          }
        });

        req.pipe(proxyReq);
        return;
      }

      // Download Android Companion APK
      if (pathname === '/youpi-sms-gateway.apk' || pathname === '/api/v1/admin/sms-gateway/download-apk') {
        const apkCandidates = [
          path.resolve(__dirname, '../public/youpi-sms-gateway.apk'),
          path.resolve(__dirname, '../../payment-api/public/youpi-sms-gateway.apk'),
          path.resolve(__dirname, '../../android-observer-app/youpi-sms-gateway.apk')
        ];
        let apkPath = null;
        for (const p of apkCandidates) {
          if (fs.existsSync(p)) {
            apkPath = p;
            break;
          }
        }
        if (apkPath) {
          const stat = fs.statSync(apkPath);
          res.writeHead(200, {
            'Content-Type': 'application/vnd.android.package-archive',
            'Content-Disposition': 'attachment; filename="youpi-sms-gateway.apk"',
            'Content-Length': stat.size,
            'Access-Control-Allow-Origin': '*'
          });
          const stream = fs.createReadStream(apkPath);
          stream.pipe(res);
          return;
        }
      }

      // Self-hosted UI fonts
      const fontMatch = /^\/fonts\/(dm-sans|sora)\.woff2$/.exec(pathname);
      if (fontMatch && req.method === 'GET') {
        const fontPath = path.resolve(__dirname, '../public/fonts', `${fontMatch[1]}.woff2`);
        if (fs.existsSync(fontPath)) {
          res.writeHead(200, {
            'Content-Type': 'font/woff2',
            'Cache-Control': 'public, max-age=31536000, immutable',
            'X-Content-Type-Options': 'nosniff'
          });
          fs.createReadStream(fontPath).pipe(res);
          return;
        }
      }

      // Dashboard View: GET / or GET /admin
      if (pathname === '/' || pathname === '/admin') {
        const html = this.renderHtml();
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache',
          ...BASE_SECURITY_HEADERS
        });
        res.end(html);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Admin Route Not Found');
    });
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}