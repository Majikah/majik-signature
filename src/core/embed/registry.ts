/**
 * registry.ts — FormatHandlerRegistry
 *
 * Maintains an ordered list of format handlers.
 * Handlers are tried in registration order; the first canHandle() match wins.
 * FallbackHandler is always last.
 */

import { FormatHandler } from "../types";
import { FallbackHandler } from "./fallback";

export class FormatHandlerRegistry {
  private readonly _handlers: FormatHandler[] = [];
  private readonly _fallback: FallbackHandler = new FallbackHandler();

  /**
   * Register a handler. Handlers registered earlier take priority.
   */
  register(handler: FormatHandler): this {
    this._handlers.push(handler);
    return this;
  }

  /**
   * Find the best handler for the given bytes and MIME type.
   * Always returns a handler (falls through to FallbackHandler).
   */
  resolve(bytes: Uint8Array, mimeType?: string): FormatHandler {
    for (const handler of this._handlers) {
      if (handler.canHandle(bytes, mimeType)) return handler;
    }
    return this._fallback;
  }

  /**
   * List all registered handler names (for debugging).
   */
  listHandlers(): string[] {
    return [...this._handlers.map((h) => h.name), this._fallback.name];
  }
}
