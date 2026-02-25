import * as crypto from 'crypto';
import * as https from 'https';
import { URL } from 'url';
import { randomNonceV4, unixTimestampSeconds } from './utils';

export interface SignedClientConfig {
  apiBaseUrl: string;
  apiKey: string;
  signingSecret: string;
  keyVersion: number;
  timeoutMs?: number;
}

export interface SignedResponse<T = unknown> {
  status: number;
  body: T;
  headers: Record<string, string | string[] | undefined>;
}

interface RetryControl {
  allow429Retry?: boolean;
  allow500Retry?: boolean;
}

type RequestRawFn = (
  url: string,
  method: string,
  body: string,
  headers: Record<string, string>,
  timeoutMs: number,
) => Promise<SignedResponse>;

export interface SignedRequestRuntime {
  requestRawFn?: RequestRawFn;
  delayFn?: (ms: number) => Promise<void>;
  timestampFn?: () => number;
  nonceFn?: () => string;
  onAttempt?: (context: {
    attempt: number;
    method: 'POST' | 'GET';
    pathName: string;
    url: string;
    body: string;
    headers: Record<string, string>;
  }) => void;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildCanonicalPayload(body: string, timestamp: number, nonce: string, keyVersion: number): string {
  return `${body}|${timestamp}|${nonce}|${keyVersion}`;
}

function createSignature(canonicalPayload: string, signingSecret: string): string {
  return crypto.createHmac('sha256', signingSecret).update(canonicalPayload, 'utf8').digest('hex');
}

export function buildSignedHeaders(
  body: string,
  config: SignedClientConfig,
  timestamp = unixTimestampSeconds(),
  nonce = randomNonceV4(),
): Record<string, string> {
  const canonical = buildCanonicalPayload(body, timestamp, nonce, config.keyVersion);
  const signature = createSignature(canonical, config.signingSecret);
  return {
    'Content-Type': 'application/json',
    'X-CodeFence-Key': config.apiKey,
    'X-CodeFence-Timestamp': String(timestamp),
    'X-CodeFence-Nonce': nonce,
    'X-CodeFence-Key-Version': String(config.keyVersion),
    'X-CodeFence-Signature': `sha256=${signature}`,
  };
}

function requestRaw(
  url: string,
  method: string,
  body: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<SignedResponse> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = https.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers: {
          ...headers,
          'Content-Length': Buffer.byteLength(body, 'utf8'),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        res.on('end', () => {
          const rawBody = Buffer.concat(chunks).toString('utf8');
          let parsedBody: unknown = rawBody;
          try {
            parsedBody = rawBody.length > 0 ? JSON.parse(rawBody) : {};
          } catch {
            parsedBody = { message: rawBody };
          }

          resolve({
            status: res.statusCode || 0,
            body: parsedBody,
            headers: res.headers,
          });
        });
      },
    );

    req.on('error', (error) => reject(error));
    req.on('timeout', () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });

    req.write(body);
    req.end();
  });
}

function buildEndpoint(baseUrl: string, pathName: string): string {
  return `${baseUrl.replace(/\/$/, '')}${pathName}`;
}

export async function signedJsonRequest<TRequest, TResponse = unknown>(
  config: SignedClientConfig,
  method: 'POST' | 'GET',
  pathName: string,
  payload: TRequest,
  retryControl: RetryControl = { allow429Retry: true, allow500Retry: true },
  runtime: SignedRequestRuntime = {},
): Promise<SignedResponse<TResponse>> {
  // Signature verification depends on this exact JSON string being sent on the wire unchanged.
  const body = method === 'GET' ? '' : JSON.stringify(payload);
  const url = buildEndpoint(config.apiBaseUrl, pathName);
  const requestRawFn = runtime.requestRawFn || requestRaw;
  const delayFn = runtime.delayFn || delay;
  const timestampFn = runtime.timestampFn || unixTimestampSeconds;
  const nonceFn = runtime.nonceFn || randomNonceV4;

  let attempt = 0;
  const max429Retries = retryControl.allow429Retry ? 3 : 0;
  const max500Retries = retryControl.allow500Retry ? 1 : 0;
  let count429 = 0;
  let count500 = 0;

  while (true) {
    attempt += 1;
    const headers = buildSignedHeaders(body, config, timestampFn(), nonceFn());
    runtime.onAttempt?.({
      attempt,
      method,
      pathName,
      url,
      body,
      headers,
    });
    const response = await requestRawFn(url, method, body, headers, config.timeoutMs || 20000);

    if (response.status === 429 && count429 < max429Retries) {
      const backoff = [1000, 2000, 4000][count429] || 4000;
      count429 += 1;
      await delayFn(backoff);
      continue;
    }

    if (response.status >= 500 && response.status < 600 && count500 < max500Retries) {
      count500 += 1;
      await delayFn(5000);
      continue;
    }

    return response as SignedResponse<TResponse>;
  }
}
