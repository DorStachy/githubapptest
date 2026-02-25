const { buildSignedHeaders, signedJsonRequest } = require('../scripts/http-client.ts');

describe('signedJsonRequest retry behavior', () => {
  const config = {
    apiBaseUrl: 'https://api.codefence.test',
    apiKey: 'cfr_test_key',
    signingSecret: 'signing-secret',
    keyVersion: 1,
  };

  it('retries 429 responses with exponential backoff (1s, 2s, 4s)', async () => {
    const statuses = [429, 429, 429, 200];
    const calls: any[] = [];
    const delays: number[] = [];

    const response = await signedJsonRequest(
      config,
      'POST',
      '/api/v1/github/results',
      { hello: 'world' },
      { allow429Retry: true, allow500Retry: false },
      {
        requestRawFn: async (url: string, method: string, body: string, headers: Record<string, string>) => {
          calls.push({ url, method, body, headers });
          return {
            status: statuses.shift() || 200,
            body: { ok: true },
            headers: {},
          };
        },
        delayFn: async (ms: number) => {
          delays.push(ms);
        },
        timestampFn: (() => {
          let value = 1_700_000_000;
          return () => {
            value += 1;
            return value;
          };
        })(),
        nonceFn: (() => {
          let value = 0;
          return () => {
            value += 1;
            return `nonce-${value}`;
          };
        })(),
      },
    );

    expect(response.status).toBe(200);
    expect(calls).toHaveLength(4);
    expect(delays).toEqual([1000, 2000, 4000]);
  });

  it('retries one 500 response once with 5s backoff', async () => {
    const statuses = [500, 200];
    const calls: any[] = [];
    const delays: number[] = [];

    const response = await signedJsonRequest(
      config,
      'POST',
      '/api/v1/github/results',
      { hello: 'world' },
      { allow429Retry: false, allow500Retry: true },
      {
        requestRawFn: async (url: string, method: string, body: string, headers: Record<string, string>) => {
          calls.push({ url, method, body, headers });
          return {
            status: statuses.shift() || 200,
            body: { ok: true },
            headers: {},
          };
        },
        delayFn: async (ms: number) => {
          delays.push(ms);
        },
      },
    );

    expect(response.status).toBe(200);
    expect(calls).toHaveLength(2);
    expect(delays).toEqual([5000]);
  });

  it('fails fast on 400/401/403/413 with no retries', async () => {
    for (const status of [400, 401, 403, 413]) {
      const calls: any[] = [];
      const delays: number[] = [];

      const response = await signedJsonRequest(
        config,
        'POST',
        '/api/v1/github/results',
        { hello: 'world' },
        { allow429Retry: true, allow500Retry: true },
        {
          requestRawFn: async (
            url: string,
            method: string,
            body: string,
            headers: Record<string, string>,
          ) => {
            calls.push({ url, method, body, headers });
            return {
              status,
              body: { message: 'error' },
              headers: {},
            };
          },
          delayFn: async (ms: number) => {
            delays.push(ms);
          },
        },
      );

      expect(response.status).toBe(status);
      expect(calls).toHaveLength(1);
      expect(delays).toEqual([]);
    }
  });

  it('keeps HMAC stable for JSON parse/stringify round-trip payloads', () => {
    const payload = { a: 1, b: 'text', nested: { c: true } };
    const body = JSON.stringify(payload);
    const roundTripped = JSON.stringify(JSON.parse(JSON.stringify(payload)));

    const headersA = buildSignedHeaders(body, config, 1_700_000_000, 'fixed-nonce');
    const headersB = buildSignedHeaders(roundTripped, config, 1_700_000_000, 'fixed-nonce');

    expect(headersA['X-CodeFence-Signature']).toBe(headersB['X-CodeFence-Signature']);
  });
});
