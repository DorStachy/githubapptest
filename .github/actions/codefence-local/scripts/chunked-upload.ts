import {
  CompleteUploadRequest,
  NormalizedFinding,
  RunnerMetadata,
  SubmitChunkRequest,
} from './types';
import { sha256 } from './utils';
import { SignedClientConfig, SignedRequestRuntime, signedJsonRequest } from './http-client';

const CHUNK_FINDING_LIMIT = 2000;

export interface ChunkedUploadInput {
  installationId: number;
  repositoryFullName: string;
  scanRunId: string;
  findings: NormalizedFinding[];
  metadata?: Pick<
    RunnerMetadata,
    | 'defaultBranch'
    | 'llmConfidenceGate'
    | 'llmIncludeSnippets'
    | 'llmProvider'
    | 'llmEndpoint'
    | 'llmModel'
  >;
}

export interface ChunkedUploadOptions {
  requestRuntime?: SignedRequestRuntime;
}

function splitChunks<T>(items: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += chunkSize) {
    chunks.push(items.slice(index, index + chunkSize));
  }
  return chunks;
}

export async function uploadResultsInChunks(
  config: SignedClientConfig,
  input: ChunkedUploadInput,
  options: ChunkedUploadOptions = {},
): Promise<void> {
  const chunks = splitChunks(input.findings, CHUNK_FINDING_LIMIT);

  for (let index = 0; index < chunks.length; index += 1) {
    const payload: SubmitChunkRequest = {
      installationId: input.installationId,
      repositoryFullName: input.repositoryFullName,
      scanRunId: input.scanRunId,
      chunkIndex: index,
      totalChunks: chunks.length,
      idempotencyKey: sha256(`${input.scanRunId}:${index}`),
      findings: chunks[index],
    };

    const chunkResponse = await signedJsonRequest(
      config,
      'POST',
      '/api/v1/github/results/chunk',
      payload,
      undefined,
      options.requestRuntime,
    );
    if (chunkResponse.status >= 400) {
      throw new Error(
        `Chunk upload failed (chunk ${index + 1}/${chunks.length}, status=${chunkResponse.status}): ${JSON.stringify(chunkResponse.body)}`,
      );
    }
  }

  const completePayload: CompleteUploadRequest = {
    installationId: input.installationId,
    repositoryFullName: input.repositoryFullName,
    scanRunId: input.scanRunId,
    totalChunks: chunks.length,
  };
  const completeMetadata = {
    defaultBranch: input.metadata?.defaultBranch || process.env.GITHUB_DEFAULT_BRANCH || undefined,
    llmConfidenceGate: input.metadata?.llmConfidenceGate,
    llmIncludeSnippets: input.metadata?.llmIncludeSnippets,
    llmProvider: input.metadata?.llmProvider,
    llmEndpoint: input.metadata?.llmEndpoint,
    llmModel: input.metadata?.llmModel,
  };
  const hasMetadata = Object.values(completeMetadata).some((value) => {
    if (value === undefined || value === null) {
      return false;
    }
    if (typeof value === 'string') {
      return value.trim().length > 0;
    }
    return true;
  });
  if (hasMetadata) {
    completePayload.metadata = completeMetadata;
  }

  const completeResponse = await signedJsonRequest(
    config,
    'POST',
    '/api/v1/github/results/complete',
    completePayload,
    undefined,
    options.requestRuntime,
  );

  if (completeResponse.status >= 400) {
    throw new Error(
      `Chunked upload completion failed (status=${completeResponse.status}): ${JSON.stringify(completeResponse.body)}`,
    );
  }
}
