/**
 * Transport module — QQ Bot event receiving mechanisms.
 *
 * Supports two transport modes:
 *   - **WebSocket** (default): long-lived WS connection with heartbeat, RESUME, etc.
 *   - **Webhook** (HTTP callback): QQ platform POSTs events to registered path.
 */

export type { WebhookInboundEvent, WebhookTransportOptions, QQBotWebhookTarget } from "./webhook-transport.js";
export { startWebhookTransport, resolveWebhookPath } from "./webhook-transport.js";
export { verifyWebhookSignature, signValidationResponse, ed25519Sign } from "./webhook-verify.js";
