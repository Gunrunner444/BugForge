import type {
  Analysis,
  CodeEntity,
  ImportRecord,
  PaginatedResponse,
  Project,
  ProjectListResponse,
  RepositoryFile,
} from "./types";

const BASE_URL =
  typeof window !== "undefined"
    ? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
    : process.env.NEXT_PUBLIC_API_URL ?? "http://backend:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// Projects
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

    delete: (id: string) =>
      request<void>(`/api/v1/projects/${id}`, { method: "DELETE" }),

    analyze: (id: string) =>
      request<Analysis>(`/api/v1/projects/${id}/analyze`, { method: "POST" }),

    analyses: (id: string, offset = 0, limit = 20) =>
      request<{ items: Analysis[]; total: number; offset: number; limit: number }>(
        `/api/v1/projects/${id}/analyses?offset=${offset}&limit=${limit}`
      ),
  },

  analyses: {
    get: (id: string) => request<Analysis>(`/api/v1/analyses/${id}`),

    files: (id: string, offset = 0, limit = 200) =>
      request<PaginatedResponse<RepositoryFile>>(
        `/api/v1/analyses/${id}/files?offset=${offset}&limit=${limit}`
      ),

    entities: (id: string, offset = 0, limit = 200) =>
      request<PaginatedResponse<CodeEntity>>(
        `/api/v1/analyses/${id}/entities?offset=${offset}&limit=${limit}`
      ),

    imports: (id: string, offset = 0, limit = 500) =>
      request<PaginatedResponse<ImportRecord>>(
        `/api/v1/analyses/${id}/imports?offset=${offset}&limit=${limit}`
      ),
  },
};
