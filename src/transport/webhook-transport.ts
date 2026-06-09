/**
 * Webhook Transport — receive QQ Bot events via HTTP POST callbacks.
 *
 * Uses OpenClaw plugin-sdk's `registerWebhookTargetWithPluginRoute` (模式 C)
 * to register webhook HTTP routes through the framework's gateway HTTP server,
 * sharing the same port and benefiting from built-in rate limiting & in-flight guards.
 *
 * Architecture:
 *   1. On gateway startAccount, register a webhook target via plugin-sdk
 *   2. Framework routes POST requests to our handler
 *   3. Handler verifies Ed25519 signatures and dispatches events
 *   4. Returns op:12 ACK immediately, processes events asynchronously
 *   5. On account stop (abortSignal), unregister the target
 *
 * Configuration (openclaw.yaml):
 * ```yaml
 * channels:
 *   qqbot:
 *     appId: "xxx"
 *     clientSecret: "xxx"
 *     transport: webhook
 *     webhook:
 *       path: /qqbot/webhook
 * ```
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import {
  registerWebhookTargetWithPluginRoute,
  withResolvedWebhookRequestPipeline,
  resolveWebhookTargetWithAuthOrRejectSync,
  createWebhookInFlightLimiter,
  createFixedWindowRateLimiter,
  readWebhookBodyOrReject,
  type WebhookInFlightLimiter,
  type FixedWindowRateLimiter,
} from "openclaw/plugin-sdk/webhook-ingress";

import type { ResolvedQQBotAccount } from "../types.js";
import { verifyWebhookSignature, signValidationResponse } from "./webhook-verify.js";

// ============ Constants ============

const OP_DISPATCH = 0;
const OP_HTTP_CALLBACK_ACK = 12;
const OP_VALIDATION = 13;

const PLUGIN_ID = "openclaw-qqbot";
const DEFAULT_WEBHOOK_PATH = "/qqbot/webhook";

// ============ Types ============

/** Webhook target registered per account */
export interface QQBotWebhookTarget {
  path: string;
  accountId: string;
  appId: string;
  clientSecret: string;
}

/** Webhook event dispatched to the consumer */
export interface WebhookInboundEvent {
  eventType: string;
  data: unknown;
  seq?: number;
}

/** Options for starting webhook transport */
export interface WebhookTransportOptions {
  account: ResolvedQQBotAccount;
  abortSignal: AbortSignal;
  onEvent: (event: WebhookInboundEvent) => void | Promise<void>;
  onReady?: () => void;
  onError?: (error: Error) => void;
  log?: {
    info: (msg: string) => void;
    warn?: (msg: string) => void;
    error: (msg: string) => void;
    debug?: (msg: string) => void;
  };
}

// ============ Module state ============

/** Per-path target registry (shared across all accounts) */
const webhookTargets = new Map<string, QQBotWebhookTarget[]>();

/** Per-account event handler map */
const eventHandlers = new Map<string, (event: WebhookInboundEvent) => void | Promise<void>>();

/** Module-level logger (set by the last startWebhookTransport call) */
let log: WebhookTransportOptions["log"] | undefined;

/** Shared rate limiter (fixed window, per source IP) */
let rateLimiter: FixedWindowRateLimiter | null = null;

/** Shared in-flight limiter */
let inFlightLimiter: WebhookInFlightLimiter | null = null;

function ensureGuards(): { rateLimiter: FixedWindowRateLimiter; inFlightLimiter: WebhookInFlightLimiter } {
  if (!rateLimiter) {
    rateLimiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 600,
      maxTrackedKeys: 4096,
    });
  }
  if (!inFlightLimiter) {
    inFlightLimiter = createWebhookInFlightLimiter({
      maxInFlightPerKey: 8,
      maxTrackedKeys: 4096,
    });
  }
  return { rateLimiter, inFlightLimiter };
}

// ============ Main handler ============

/**
 * Shared HTTP handler for all QQBot webhook routes.
 * Registered once per unique path, dispatches to the correct account target.
 */
async function handleQQBotWebhookRequest(req: IncomingMessage, res: ServerResponse): Promise<boolean | void> {
  const guards = ensureGuards();

  const handled = await withResolvedWebhookRequestPipeline({
    req,
    res,
    targetsByPath: webhookTargets,
    rateLimiter: guards.rateLimiter,
    inFlightLimiter: guards.inFlightLimiter,
    requireJsonContentType: true,
    handle: async ({ targets }) => {
      // Read raw body (up to 1MB, 30s timeout)
      const bodyResult = await readWebhookBodyOrReject({
        req,
        res,
        maxBytes: 1024 * 1024,
        timeoutMs: 30_000,
      });
      if (!bodyResult.ok) return;

      const rawBodyStr = bodyResult.value;
      const rawBody = Buffer.from(rawBodyStr, "utf-8");
      let payload: { op: number; d?: unknown; t?: string; s?: number };
      try {
        payload = JSON.parse(rawBodyStr);
      } catch (err) {
        log?.error(`[qqbot:webhook] Failed to parse request body as JSON: ${err instanceof Error ? err.message : String(err)}, body preview: ${rawBodyStr.slice(0, 200)}`);
        res.statusCode = 400;
        res.end(JSON.stringify({ error: "invalid json" }));
        return;
      }

      // ── op:13 — Callback URL validation (before signature check) ──
      if (payload.op === OP_VALIDATION) {
        handleValidation(payload, targets, res);
        return;
      }

      // ── Signature verification → resolve target ──
      const timestamp = getHeader(req, "x-signature-timestamp") ?? "";
      const signature = getHeader(req, "x-signature-ed25519") ?? "";

      if (!timestamp || !signature) {
        log?.warn?.(`[qqbot:webhook] Missing signature headers — timestamp: "${timestamp}", signature: "${signature}", url: ${req.url}`);
        res.statusCode = 401;
        res.end(JSON.stringify({ error: "missing signature headers" }));
        return;
      }

      const matchedTarget = resolveWebhookTargetWithAuthOrRejectSync({
        targets,
        res,
        isMatch: (target) =>
          verifyWebhookSignature({
            body: rawBody,
            timestamp,
            signature,
            botSecret: target.clientSecret,
          }),
        unauthorizedStatusCode: 401,
        unauthorizedMessage: JSON.stringify({ error: "invalid signature" }),
      });

      if (!matchedTarget) {
        log?.warn?.(`[qqbot:webhook] Signature verification failed for path: ${req.url}, timestamp: ${timestamp}`);
        return; // response already sent by resolver
      }

      // ── ACK immediately ──
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ op: OP_HTTP_CALLBACK_ACK, d: 0 }));

      // ── Async dispatch (fire-and-forget) ──
      if (payload.op === OP_DISPATCH) {
        const handler = eventHandlers.get(matchedTarget.accountId);
        if (handler) {
          Promise.resolve(
            handler({
              eventType: payload.t ?? "",
              data: payload.d,
              seq: payload.s,
            }),
          ).catch((err) => {
            log?.error(`[qqbot:${matchedTarget.accountId}] Event handler error for "${payload.t}": ${err instanceof Error ? err.message : String(err)}`);
          });
        } else {
          log?.warn?.(`[qqbot:webhook] No event handler registered for account: ${matchedTarget.accountId}, event: ${payload.t}`);
        }
      }
    },
  });

  return handled;
}

// ============ Validation handler (op:13) ============

function handleValidation(
  payload: { d?: unknown },
  targets: QQBotWebhookTarget[],
  res: ServerResponse,
): void {
  const d = payload.d as { plain_token?: string; event_ts?: string } | undefined;

  if (!d?.plain_token || !d?.event_ts) {
    log?.warn?.(`[qqbot:webhook] Invalid validation payload (op:13): missing plain_token or event_ts, got: ${JSON.stringify(d)}`);
    res.statusCode = 400;
    res.end(JSON.stringify({ error: "invalid validation payload" }));
    return;
  }

  // Use the first target's secret for validation
  // (op:13 is sent during URL registration, only one bot should be using the path at that time)
  const target = targets[0];
  if (!target) {
    log?.error(`[qqbot:webhook] No target registered for validation (op:13), cannot sign response`);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "no target registered" }));
    return;
  }

  const response = signValidationResponse({
    plainToken: d.plain_token,
    eventTs: d.event_ts,
    botSecret: target.clientSecret,
  });

  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(response));
}

// ============ Public API ============

/**
 * Start the webhook transport for a given account.
 *
 * Registers a webhook target on the framework's plugin HTTP route system.
 * The handler verifies Ed25519 signatures, ACKs immediately, and dispatches
 * events asynchronously via the provided `onEvent` callback.
 *
 * Returns when the abortSignal is triggered (account stopped).
 */
export async function startWebhookTransport(opts: WebhookTransportOptions): Promise<void> {
  const { account, abortSignal, onEvent, onReady, onError, log: optLog } = opts;
  log = optLog;
  const webhookPath = account.config.webhook?.path ?? DEFAULT_WEBHOOK_PATH;

  log?.info(`[qqbot:${account.accountId}] Starting webhook transport on path: ${webhookPath}`);

  // Register event handler for this account
  eventHandlers.set(account.accountId, onEvent);

  // Register webhook target + plugin HTTP route
  const { unregister } = registerWebhookTargetWithPluginRoute({
    targetsByPath: webhookTargets,
    target: {
      path: webhookPath,
      accountId: account.accountId,
      appId: account.appId,
      clientSecret: account.clientSecret,
    },
    route: {
      auth: "plugin",
      match: "exact" as const,
      pluginId: PLUGIN_ID,
      source: "qqbot-webhook",
      accountId: account.accountId,
      replaceExisting: true,
      log: (msg: string) => log?.info(msg),
      handler: handleQQBotWebhookRequest,
    },
    onLastPathTargetRemoved: () => {
      log?.info(`[qqbot] Last webhook target removed from path: ${webhookPath}`);
    },
  });

  log?.info(`[qqbot:${account.accountId}] Webhook transport registered on path: ${webhookPath}`);
  onReady?.();

  // Wait until abort signal fires
  await new Promise<void>((resolve) => {
    if (abortSignal.aborted) {
      resolve();
      return;
    }
    abortSignal.addEventListener("abort", () => resolve(), { once: true });
  });

  // Cleanup
  unregister();
  eventHandlers.delete(account.accountId);
  log?.info(`[qqbot:${account.accountId}] Webhook transport stopped`);
}

/**
 * Resolve the webhook path for a given account (for external configuration / setWebhook calls).
 */
export function resolveWebhookPath(account: ResolvedQQBotAccount): string {
  return account.config.webhook?.path ?? DEFAULT_WEBHOOK_PATH;
}

// ============ Helpers ============

function getHeader(req: IncomingMessage, key: string): string | undefined {
  const val = req.headers[key];
  if (Array.isArray(val)) return val[0];
  return val;
}
