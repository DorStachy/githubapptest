/**
 * WebSocket handler — INTENTIONALLY VULNERABLE for CodeFence testing.
 *
 * Covers: missing origin validation, no message size limit, prototype pollution
 *         via JSON.parse, eval-based message handling, unvalidated broadcast,
 *         and SAFE counterparts.
 */

const WebSocket = require('ws');
const vm = require('vm');

// ─────────────────────── NO ORIGIN VALIDATION (HIGH) ────────────────────
const wss = new WebSocket.Server({ port: 8080 });
// Missing: verifyClient callback to check Origin header

wss.on('connection', (ws, req) => {
  console.log(`New connection from ${req.headers.origin}`);

  ws.on('message', (raw) => {
    // ─── NO SIZE LIMIT (MEDIUM) — could receive GB of data ───────
    const msg = raw.toString();

    try {
      const data = JSON.parse(msg);

      // ─── EVAL-BASED DISPATCH (CRITICAL) ──────────────────────
      // Attacker sends: { "action": "require('child_process').execSync('id')" }
      if (data.action) {
        const result = eval(data.action);
        ws.send(JSON.stringify({ result }));
      }

      // ─── PROTOTYPE POLLUTION VIA MERGE (HIGH) ────────────────
      if (data.settings) {
        const config = {};
        Object.assign(config, data.settings);
        // If data.settings contains __proto__, it pollutes Object.prototype
      }

      // ─── UNVALIDATED BROADCAST (MEDIUM) ──────────────────────
      // Any connected client can broadcast to all — no auth check
      if (data.broadcast) {
        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(data.broadcast);  // XSS if rendered as HTML
          }
        });
      }

      // ─── VM SANDBOX ESCAPE (HIGH) ────────────────────────────
      if (data.compute) {
        // vm.runInNewContext is NOT a security sandbox
        const sandbox = { result: null };
        vm.runInNewContext(`result = ${data.compute}`, sandbox);
        ws.send(JSON.stringify({ computed: sandbox.result }));
      }

    } catch (e) {
      // ─── ERROR LEAK (LOW) ────────────────────────────────────
      ws.send(JSON.stringify({ error: e.message, stack: e.stack }));
    }
  });
});

// ═══════════════════════════════════════════════════════════════════
// SAFE WEBSOCKET SERVER (no vulns — should NOT flag)
// ═══════════════════════════════════════════════════════════════════

const ALLOWED_ORIGINS = ['https://app.example.com', 'https://staging.example.com'];
const MAX_MESSAGE_SIZE = 1024 * 64; // 64KB

const safeWss = new WebSocket.Server({
  port: 8081,
  maxPayload: MAX_MESSAGE_SIZE,
  verifyClient: (info) => {
    return ALLOWED_ORIGINS.includes(info.origin);
  },
});

const SAFE_ACTIONS = {
  ping: () => ({ pong: Date.now() }),
  status: () => ({ connections: safeWss.clients.size }),
};

safeWss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw.toString());

      if (typeof data.action !== 'string') {
        ws.send(JSON.stringify({ error: 'invalid action' }));
        return;
      }

      const handler = SAFE_ACTIONS[data.action];
      if (!handler) {
        ws.send(JSON.stringify({ error: 'unknown action' }));
        return;
      }

      ws.send(JSON.stringify(handler()));
    } catch {
      ws.send(JSON.stringify({ error: 'invalid message' }));
    }
  });
});
