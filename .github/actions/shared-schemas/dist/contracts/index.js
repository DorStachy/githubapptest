"use strict";
/**
 * Canonical contract types for the CodeFence scanner pipeline.
 *
 * These are the single source of truth for message shapes flowing between:
 *   Backend (dispatch) → Scanner Worker → Scan Processor
 *   Backend (results ingestion) → Scan Processor
 *
 * All consumers MUST import these types from @cera/shared-schemas.
 */
Object.defineProperty(exports, "__esModule", { value: true });
