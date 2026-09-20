import type {
  Analysis,
  AIStatus,
  SecurityFinding,
  SecurityStatus,
  SecurityTestingSessionResponse,
  AuthorizationDecision,
  AutonomousRun,
  AutonomousRunsListResponse,
  BugReproductionSession,
  ReproductionSessionsListResponse,
  CandidateStatusCounts,
  CodeEntity,
  DebuggingHypothesis,
  DebuggingSession,
  DebuggingSessionsListResponse,
  DiscoveryRun,
  DiscoveryRunsListResponse,
  DiscoverySettings,
  Finding,
  FindingsListResponse,
  GeneratedTest,
  GeneratedTestsListResponse,
  ImportRecord,
  PaginatedResponse,
  PatchCandidate,
  PatchVerification,
  Project,
  ProjectListResponse,
  RepairSession,
  RepairSessionsListResponse,
  RepositoryCandidate,
  RepositoryCandidatesListResponse,
  RepositoryFile,
  TestGenerationSession,
  TestGenSessionsListResponse,
  TestRun,
  TestRunListResponse,
  TestResultListResponse,
  GitHubRepository,
  GitHubDelivery,
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
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(typeof window !== "undefined" && sessionStorage.getItem("bugforge_operator_token")
          ? { "X-BugForge-Operator-Token": sessionStorage.getItem("bugforge_operator_token") as string }
          : {}),
        ...init?.headers,
      },
      signal: controller.signal,
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

    generateTests: (
      id: string,
      opts: { analysis_id?: string; test_run_id?: string; debugging_session_id?: string } = {}
    ) =>
      request<TestGenerationSession>(`/api/v1/projects/${id}/test-generation`, {
        method: "POST",
        body: JSON.stringify(opts),
      }),

    testGenSessions: (id: string, offset = 0, limit = 20) =>
      request<TestGenSessionsListResponse>(
        `/api/v1/projects/${id}/test-generation?offset=${offset}&limit=${limit}`,
      ),

    generatedTests: (id: string, offset = 0, limit = 50) =>
      request<GeneratedTestsListResponse>(
        `/api/v1/projects/${id}/generated-tests?offset=${offset}&limit=${limit}`,
      ),

    reproduce: (id: string, opts: {hypothesis_id?: string; generated_test_id?: string; debugging_session_id?: string; total_attempts?: number} = {}) =>
      request<BugReproductionSession>(`/api/v1/projects/${id}/reproduction`, {
        method: "POST",
        body: JSON.stringify(opts),
      }),

    reproductionSessions: (id: string, offset = 0, limit = 20) =>
      request<ReproductionSessionsListResponse>(
        `/api/v1/projects/${id}/reproduction?offset=${offset}&limit=${limit}`,
      ),

    startRepair: (
      id: string,
      opts: {
        hypothesis_id?: string;
        reproduction_session_id?: string;
        debugging_session_id?: string;
        max_candidates?: number;
      } = {},
    ) =>
      request<RepairSession>(`/api/v1/projects/${id}/repair`, {
        method: "POST",
        body: JSON.stringify(opts),
      }),

    repairSessions: (id: string, offset = 0, limit = 20) =>
      request<RepairSessionsListResponse>(
        `/api/v1/projects/${id}/repair?offset=${offset}&limit=${limit}`,
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
  testGeneration: {
    get: (sessionId: string) =>
      request<TestGenerationSession>(`/api/v1/test-generation/${sessionId}`),
    tests: (sessionId: string, offset = 0, limit = 50) =>
      request<GeneratedTestsListResponse>(
        `/api/v1/test-generation/${sessionId}/tests?offset=${offset}&limit=${limit}`,
      ),

  },

  reproduction: {
    get: (sessionId: string) =>
      request<BugReproductionSession>(`/api/v1/reproduction/${sessionId}`),

    attempts: (sessionId: string) =>
      request<BugReproductionSession>(`/api/v1/reproduction/${sessionId}/attempts`),
  },

  repair: {
    get: (sessionId: string) => request<RepairSession>(`/api/v1/repair/${sessionId}`),

    candidates: (sessionId: string) =>
      request<PatchCandidate[]>(`/api/v1/repair/${sessionId}/candidates`),

    candidate: (sessionId: string, candidateId: string) =>
      request<PatchCandidate>(`/api/v1/repair/${sessionId}/candidates/${candidateId}`),

    startVerification: (sessionId: string, candidateId: string) =>
      request<PatchVerification>(
        `/api/v1/repair/${sessionId}/candidates/${candidateId}/verify`,
        { method: "POST" }
      ),

    getVerification: (sessionId: string, candidateId: string) =>
      request<PatchVerification>(
        `/api/v1/repair/${sessionId}/candidates/${candidateId}/verify`
      ),

    listVerifications: (sessionId: string) =>
      request<PatchVerification[]>(`/api/v1/repair/${sessionId}/verifications`),
  },

  github: {
    getRepo: (projectId: string) =>
      request<GitHubRepository>(`/api/v1/projects/${projectId}/github`),

    connect: (projectId: string, owner: string, repo: string) =>
      request<GitHubRepository>(`/api/v1/projects/${projectId}/github/connect`, {
        method: "POST",
        body: JSON.stringify({ owner, repo }),
      }),

    disconnect: (projectId: string) =>
      request<void>(`/api/v1/projects/${projectId}/github`, { method: "DELETE" }),

    deliver: (projectId: string, candidateId: string) =>
      request<GitHubDelivery>(
        `/api/v1/projects/${projectId}/github/deliver/${candidateId}`,
        { method: "POST" }
      ),

    listDeliveries: (projectId: string) =>
      request<GitHubDelivery[]>(`/api/v1/projects/${projectId}/github/deliveries`),

    getDelivery: (deliveryId: string) =>
      request<GitHubDelivery>(`/api/v1/github/deliveries/${deliveryId}`),
  },

  // ── v1.1.0 Autonomous Discovery ─────────────────────────────────────────

  discovery: {
    triggerRun: (maxPages = 5) =>
      request<DiscoveryRun>("/api/v1/discovery/run", {
        method: "POST",
        body: JSON.stringify({ max_pages: maxPages }),
      }),

    listRuns: (offset = 0, limit = 20) =>
      request<DiscoveryRunsListResponse>(
        `/api/v1/discovery/runs?offset=${offset}&limit=${limit}`,
      ),

    getRun: (id: string) => request<DiscoveryRun>(`/api/v1/discovery/runs/${id}`),

    getSettings: () => request<DiscoverySettings>("/api/v1/discovery/settings"),
  },

  candidates: {
    list: (status?: string, offset = 0, limit = 50) => {
      const params = new URLSearchParams({ offset: String(offset), limit: String(limit) });
      if (status) params.set("eligibility_status", status);
      return request<RepositoryCandidatesListResponse>(
        `/api/v1/repositories/discovered?${params}`,
      );
    },

    counts: () => request<CandidateStatusCounts>("/api/v1/repositories/discovered/counts"),

    get: (id: string) =>
      request<RepositoryCandidate>(`/api/v1/repositories/discovered/${id}`),

    analyze: (id: string, forceRescan = false) =>
      request<AutonomousRun>(`/api/v1/repositories/discovered/${id}/analyze`, {
        method: "POST",
        body: JSON.stringify({ force_rescan: forceRescan }),
      }),
  },

  autonomous: {
    listRuns: (status?: string, offset = 0, limit = 50) => {
      const params = new URLSearchParams({ offset: String(offset), limit: String(limit) });
      if (status) params.set("status", status);
      return request<AutonomousRunsListResponse>(`/api/v1/autonomous/runs?${params}`);
    },

    getRun: (id: string) => request<AutonomousRun>(`/api/v1/autonomous/runs/${id}`),

    cancelRun: (id: string) =>
      request<AutonomousRun>(`/api/v1/autonomous/runs/${id}/cancel`, { method: "POST" }),
  },

  ai: {
    status: () => request<AIStatus>("/api/v1/ai/status"),

    test: (prompt = "Reply with only the word: ok") =>
      request<{ provider: string; model: string; response: string; duration_seconds: number; error: string | null }>(
        "/api/v1/ai/test",
        { method: "POST", body: JSON.stringify({ prompt }) },
      ),
  },

  security: {
    status: () => request<SecurityStatus>("/api/v1/security/status"),
    findings: (projectId: string, offset = 0, limit = 100) =>
      request<{ items: SecurityFinding[]; total: number; offset: number; limit: number }>(
        `/api/v1/security/findings?project_id=${projectId}&offset=${offset}&limit=${limit}`,
      ),
  },

  securityTesting: {
    createSession: (body: Record<string, unknown>) =>
      request<SecurityTestingSessionResponse>("/api/v1/security-testing/sessions", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    getSession: (projectId: string) =>
      request<SecurityTestingSessionResponse>(`/api/v1/security-testing/sessions/${projectId}`),
    authorize: (projectId: string, body: Record<string, unknown>) =>
      request<AuthorizationDecision>(`/api/v1/security-testing/sessions/${projectId}/authorize`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    tools: () => request<{ browsers: string[]; proxies: string[]; security_tools: string[]; fuzzers: string[] }>(
      "/api/v1/security-testing/tools",
    ),
    audit: (projectId: string) =>
      request<{ entries: Array<Record<string, unknown>>; chain_valid: boolean }>(
        `/api/v1/security-testing/sessions/${projectId}/audit`,
      ),
  },

  research: {
    createSession: (body: Record<string, unknown>) =>
      request<Record<string, unknown>>("/api/v1/security-agent/sessions", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    getSession: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}`),
    dashboard: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/dashboard`),
    timeline: (id: string, params?: Record<string, string>) => {
      const query = new URLSearchParams(params);
      const suffix = query.toString() ? `?${query}` : "";
      return request<Record<string, unknown>>(
        `/api/v1/security-agent/sessions/${id}/timeline${suffix}`,
      );
    },
    step: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/step`, {
        method: "POST",
      }),
    override: (id: string, body: Record<string, unknown>) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/override`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    reviewNext: (id: string, body: Record<string, unknown>) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/next-action/review`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    findings: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/findings`),
    evidence: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/evidence`),
    graph: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/graph`),
    identities: (id: string) =>
      request<Record<string, unknown>>(`/api/v1/security-agent/sessions/${id}/identities`),
    exportPackage: (id: string, findingId?: string) => {
      const suffix = findingId ? `?finding_id=${encodeURIComponent(findingId)}` : "";
      return request<Record<string, unknown>>(
        `/api/v1/security-agent/sessions/${id}/export${suffix}`,
      );
    },
    createProject: (body: Record<string, unknown>) =>
      request<Record<string, unknown>>("/api/v1/security-agent/research-projects", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },

  hackerone: {
    status: () => request<Record<string, unknown>>("/api/v1/hackerone/status"),
    sync: (handle: string) =>
      request<Record<string, unknown>>("/api/v1/hackerone/programs/sync", {
        method: "POST",
        body: JSON.stringify({ handle }),
      }),
    program: (handle: string) => request<Record<string, unknown>>(`/api/v1/hackerone/programs/${handle}`),
    createDraft: (body: Record<string, unknown>) =>
      request<Record<string, unknown>>("/api/v1/hackerone/reports/drafts", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    review: (draftId: string, programHandle: string) =>
      request<Record<string, unknown>>(`/api/v1/hackerone/reports/${draftId}/review`, {
        method: "POST",
        body: JSON.stringify({ program_handle: programHandle }),
      }),
    dryRun: (draftId: string, programHandle: string) =>
      request<Record<string, unknown>>(`/api/v1/hackerone/reports/${draftId}/dry-run`, {
        method: "POST",
        body: JSON.stringify({ program_handle: programHandle }),
      }),
    approve: (draftId: string, programHandle: string) =>
      request<Record<string, unknown>>(`/api/v1/hackerone/reports/${draftId}/approve`, {
        method: "POST",
        body: JSON.stringify({ program_handle: programHandle }),
      }),
    submit: (draftId: string, programHandle: string) =>
      request<Record<string, unknown>>(`/api/v1/hackerone/reports/${draftId}/submit`, {
        method: "POST",
        body: JSON.stringify({ program_handle: programHandle }),
      }),
    reconcile: (draftId: string) =>
      request<Record<string, unknown>>(`/api/v1/hackerone/reports/${draftId}/reconcile`, {
        method: "POST",
        body: JSON.stringify({}),
      }),
  },
};