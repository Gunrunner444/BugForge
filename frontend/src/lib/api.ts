import type {
  Analysis,
  CodeEntity,
  DebuggingSession,
  DebuggingSessionsListResponse,
  DebuggingHypothesis,
  Finding,
  FindingsListResponse,
  ImportRecord,
  PaginatedResponse,
  Project,
  ProjectListResponse,
  RepositoryFile,
  TestRun,
  TestRunListResponse,
  TestResultListResponse,
} from "./types";

const BASE_URL =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000")
    : (process.env.NEXT_PUBLIC_API_URL ?? "http://backend:8000");

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly detail?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30_000);

  let res: Response;
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json", ...init?.headers },
      signal: controller.signal,
      ...init,
    });
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(0, "Request timed out");
    }
    throw new ApiError(0, "Network error — is the backend running?");
  } finally {
    clearTimeout(timeoutId);
  }

  if (!res.ok) {
    let detail: string | undefined;
    try {
      const body = (await res.json()) as { detail?: unknown };
      detail =
        typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      detail = await res.text().catch(() => undefined);
    }
    throw new ApiError(res.status, `HTTP ${res.status}`, detail);
  }

  if (res.status === 204) return undefined as unknown as T;

  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError(res.status, "Invalid JSON from server");
  }
}

export const api = {
  projects: {
    list: (offset = 0, limit = 50) =>
      request<ProjectListResponse>(`/api/v1/projects?offset=${offset}&limit=${limit}`),

    get: (id: string) => request<Project>(`/api/v1/projects/${id}`),

    create: (data: { name: string; description?: string; repository_path: string }) =>
      request<Project>("/api/v1/projects", {
        method: "POST",
        body: JSON.stringify(data),
      }),

    delete: (id: string) => request<void>(`/api/v1/projects/${id}`, { method: "DELETE" }),

    analyze: (id: string) =>
      request<Analysis>(`/api/v1/projects/${id}/analyze`, { method: "POST" }),

    analyses: (id: string, offset = 0, limit = 20) =>
      request<{ items: Analysis[]; total: number; offset: number; limit: number }>(
        `/api/v1/projects/${id}/analyses?offset=${offset}&limit=${limit}`,
      ),

    runTests: (id: string) =>
      request<TestRun>(`/api/v1/projects/${id}/tests/run`, { method: "POST" }),

    testRuns: (id: string, offset = 0, limit = 20) =>
      request<TestRunListResponse>(
        `/api/v1/projects/${id}/test-runs?offset=${offset}&limit=${limit}`,
      ),

    debug: (id: string, analysisId?: string, testRunId?: string) =>
      request<DebuggingSession>(`/api/v1/projects/${id}/debug`, {
        method: "POST",
        body: JSON.stringify({
          analysis_id: analysisId ?? null,
          test_run_id: testRunId ?? null,
        }),
      }),

    debugSessions: (id: string, offset = 0, limit = 20) =>
      request<DebuggingSessionsListResponse>(
        `/api/v1/projects/${id}/debugging?offset=${offset}&limit=${limit}`,
      ),
  },

  analyses: {
    get: (id: string) => request<Analysis>(`/api/v1/analyses/${id}`),

    files: (id: string, offset = 0, limit = 200) =>
      request<PaginatedResponse<RepositoryFile>>(
        `/api/v1/analyses/${id}/files?offset=${offset}&limit=${limit}`,
      ),

    entities: (id: string, offset = 0, limit = 200) =>
      request<PaginatedResponse<CodeEntity>>(
        `/api/v1/analyses/${id}/entities?offset=${offset}&limit=${limit}`,
      ),

    imports: (id: string, offset = 0, limit = 500) =>
      request<PaginatedResponse<ImportRecord>>(
        `/api/v1/analyses/${id}/imports?offset=${offset}&limit=${limit}`,
      ),

    findings: (id: string, severity?: string, category?: string, offset = 0, limit = 200) => {
      const params = new URLSearchParams({ offset: String(offset), limit: String(limit) });
      if (severity) params.set("severity", severity);
      if (category) params.set("category", category);
      return request<FindingsListResponse>(`/api/v1/analyses/${id}/findings?${params}`);
    },
  },

  testRuns: {
    get: (id: string) => request<TestRun>(`/api/v1/test-runs/${id}`),

    results: (id: string, offset = 0, limit = 500) =>
      request<TestResultListResponse>(
        `/api/v1/test-runs/${id}/results?offset=${offset}&limit=${limit}`,
      ),
  },

  debugging: {
    get: (sessionId: string) =>
      request<DebuggingSession>(`/api/v1/debugging/${sessionId}`),

    hypotheses: (sessionId: string) =>
      request<DebuggingHypothesis[]>(`/api/v1/debugging/${sessionId}/hypotheses`),
  },
};
