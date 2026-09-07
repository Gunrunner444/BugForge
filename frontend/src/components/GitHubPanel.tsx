"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { GitHubDelivery, GitHubRepository } from "@/lib/types";
import { formatDate } from "@/lib/utils";

interface Props {
  projectId: string;
}

const DELIVERY_STATUS_STYLES: Record<string, { badge: string; label: string }> = {
  pending: { badge: "bg-slate-100 text-slate-600", label: "Pending" },
  preparing: { badge: "bg-blue-100 text-blue-700", label: "Preparing" },
  final_verification: { badge: "bg-indigo-100 text-indigo-700", label: "Final Verification" },
  branch_created: { badge: "bg-cyan-100 text-cyan-700", label: "Branch Created" },
  committing: { badge: "bg-teal-100 text-teal-700", label: "Committing" },
  pushing: { badge: "bg-sky-100 text-sky-700", label: "Pushing" },
  pr_created: { badge: "bg-violet-100 text-violet-700", label: "PR Created" },
  completed: { badge: "bg-emerald-100 text-emerald-800", label: "Completed" },
  failed: { badge: "bg-red-100 text-red-700", label: "Failed" },
  aborted: { badge: "bg-orange-100 text-orange-700", label: "Aborted" },
};

function DeliveryRow({ delivery }: { delivery: GitHubDelivery }) {
  const style = DELIVERY_STATUS_STYLES[delivery.status] ?? DELIVERY_STATUS_STYLES.pending;
  return (
    <div className="border border-slate-200 rounded-lg p-4 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${style.badge}`}>
          {style.label}
        </span>
        <span className="text-xs text-slate-500">
          Branch: <code className="bg-slate-100 px-1 rounded">{delivery.delivery_branch}</code>
        </span>
        {delivery.commit_sha && (
          <span className="text-xs text-slate-500">
            Commit: <code className="bg-slate-100 px-1 rounded">{delivery.commit_sha.slice(0, 8)}</code>
          </span>
        )}
      </div>

      {delivery.pull_request_url && (
        <a
          href={delivery.pull_request_url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-indigo-600 hover:underline font-medium"
        >
          PR #{delivery.pull_request_number} on GitHub →
        </a>
      )}

      {delivery.status === "failed" && delivery.error_message && (
        <p className="text-xs text-red-600 bg-red-50 rounded p-2 font-mono whitespace-pre-wrap">
          {delivery.error_message}
        </p>
      )}

      <div className="text-xs text-slate-400">
        Started: {delivery.started_at ? formatDate(delivery.started_at) : "Not started"}
        {delivery.completed_at && ` · Completed: ${formatDate(delivery.completed_at)}`}
      </div>
    </div>
  );
}

export default function GitHubPanel({ projectId }: Props) {
  const [repo, setRepo] = useState<GitHubRepository | null>(null);
  const [deliveries, setDeliveries] = useState<GitHubDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [owner, setOwner] = useState("");
  const [repoName, setRepoName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [repoResult, deliveriesResult] = await Promise.allSettled([
        api.github.getRepo(projectId),
        api.github.listDeliveries(projectId),
      ]);
      if (repoResult.status === "fulfilled") setRepo(repoResult.value);
      if (deliveriesResult.status === "fulfilled") setDeliveries(deliveriesResult.value);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  const handleConnect = async () => {
    setConnecting(true);
    setError(null);
    try {
      const connected = await api.github.connect(projectId, owner.trim(), repoName.trim());
      setRepo(connected);
      setOwner("");
      setRepoName("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!confirm("Disconnect this GitHub repository from the project?")) return;
    try {
      await api.github.disconnect(projectId);
      setRepo(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  };

  if (loading) {
    return <div className="text-sm text-slate-500 py-4">Loading GitHub integration…</div>;
  }

  return (
    <div className="space-y-6">
      {/* Connected repository */}
      {repo ? (
        <div className="border border-slate-200 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-900">
                {repo.owner}/{repo.repo}
              </span>
              <span
                className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                  repo.connected
                    ? "bg-emerald-100 text-emerald-800"
                    : "bg-red-100 text-red-700"
                }`}
              >
                {repo.connected ? "Connected" : "Not connected"}
              </span>
            </div>
            <button
              onClick={handleDisconnect}
              className="text-xs text-red-500 hover:text-red-700"
            >
              Disconnect
            </button>
          </div>
          <div className="text-xs text-slate-500 space-y-1">
            <div>
              Default branch:{" "}
              <code className="bg-slate-100 px-1 rounded">{repo.default_branch}</code>
            </div>
            <div>
              <a
                href={repo.html_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-600 hover:underline"
              >
                {repo.html_url}
              </a>
            </div>
          </div>
        </div>
      ) : (
        /* Connect form */
        <div className="border border-dashed border-slate-300 rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-semibold text-slate-700">Connect a GitHub Repository</h3>
          <p className="text-xs text-slate-500">
            Enter the owner and repository name to connect this BugForge project to a GitHub
            repository. A GitHub token must be configured server-side.
          </p>
          <div className="flex gap-2 items-center">
            <input
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="owner"
              className="border border-slate-300 rounded px-3 py-1.5 text-sm w-32 focus:outline-none focus:ring-2 focus:ring-indigo-400"
            />
            <span className="text-slate-400">/</span>
            <input
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder="repo"
              className="border border-slate-300 rounded px-3 py-1.5 text-sm w-48 focus:outline-none focus:ring-2 focus:ring-indigo-400"
            />
            <button
              onClick={handleConnect}
              disabled={connecting || !owner.trim() || !repoName.trim()}
              className="px-4 py-1.5 bg-indigo-600 text-white text-sm rounded hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              {connecting ? "Connecting…" : "Connect"}
            </button>
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>
      )}

      {/* Deliveries */}
      {deliveries.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-700">
            Deliveries ({deliveries.length})
          </h3>
          <div className="space-y-2">
            {deliveries.map((d) => (
              <DeliveryRow key={d.id} delivery={d} />
            ))}
          </div>
        </div>
      )}

      {repo && deliveries.length === 0 && (
        <p className="text-sm text-slate-500">
          No deliveries yet. Verify a patch candidate and use "Deliver to GitHub" to create a pull
          request.
        </p>
      )}
    </div>
  );
}
