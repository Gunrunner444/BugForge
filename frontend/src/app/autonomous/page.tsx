"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { AutonomousRun } from "@/lib/types";

const STATUS_COLOURS: Record<string, string> = {
  queued: "bg-gray-100 text-gray-600",
  screening: "bg-blue-100 text-blue-700",
  acquiring: "bg-blue-100 text-blue-700",
  static_analyzing: "bg-yellow-100 text-yellow-700",
  ai_analyzing: "bg-purple-100 text-purple-700",
  finding_validation: "bg-indigo-100 text-indigo-700",
  completed: "bg-green-100 text-green-700",
  failed: "bg-red-100 text-red-700",
  cancelled: "bg-gray-100 text-gray-500",
  inconclusive: "bg-orange-100 text-orange-700",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLOURS[status] ?? "bg-gray-100 text-gray-700";
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export default function AutonomousPage() {
  const [runs, setRuns] = useState<AutonomousRun[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);

  const limit = 50;

  async function loadData(newOffset = 0, newStatus = statusFilter) {
    setLoading(true);
    setError(null);
    try {
      const resp = await api.autonomous.listRuns(newStatus || undefined, newOffset, limit);
      setRuns(resp.items);
      setTotal(resp.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load runs");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    // Poll for active runs every 10s
    const interval = setInterval(() => {
      loadData(offset, statusFilter);
    }, 10_000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function cancelRun(id: string) {
    setCancelling(id);
    try {
      await api.autonomous.cancelRun(id);
      await loadData(offset, statusFilter);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to cancel run");
    } finally {
      setCancelling(null);
    }
  }

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;
  const terminal = new Set(["completed", "failed", "cancelled", "inconclusive"]);

  return (
    <div className="max-w-6xl mx-auto py-8 px-4">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Autonomous Analysis Runs</h1>
          <p className="mt-1 text-sm text-gray-500">
            Each row tracks one repository&apos;s progress through the analysis pipeline.
          </p>
        </div>
        <Link
          href="/repositories"
          className="px-4 py-2 rounded-lg border border-gray-300 text-sm text-gray-700 hover:bg-gray-50"
        >
          Queue from Repositories
        </Link>
      </div>

      {error && (
        <div className="mb-4 rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Status filter pills */}
      <div className="mb-4 flex flex-wrap gap-2">
        {["", "queued", "screening", "acquiring", "static_analyzing", "ai_analyzing",
          "finding_validation", "completed", "failed", "cancelled"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => { setStatusFilter(s); setOffset(0); loadData(0, s); }}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
              statusFilter === s
                ? "border-indigo-500 bg-indigo-50 text-indigo-700"
                : "border-gray-200 bg-white text-gray-600 hover:border-gray-300"
            }`}
          >
            {s || "all"}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-100 text-sm text-gray-500">
          {total} run{total !== 1 ? "s" : ""}
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-gray-400">Loading…</div>
        ) : runs.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-400">
            No analysis runs yet.{" "}
            <Link href="/repositories" className="text-indigo-600 hover:underline">
              Select an eligible repository to analyze.
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-xs font-medium text-gray-500 uppercase">
                <tr>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Stage</th>
                  <th className="px-4 py-3 text-left">Model</th>
                  <th className="px-4 py-3 text-right">Static</th>
                  <th className="px-4 py-3 text-right">AI Hyp</th>
                  <th className="px-4 py-3 text-right">Validated</th>
                  <th className="px-4 py-3 text-left">Commit</th>
                  <th className="px-4 py-3 text-left">Started</th>
                  <th className="px-4 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {runs.map((run) => (
                  <tr key={run.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <StatusBadge status={run.status} />
                      {run.error_message && (
                        <p className="text-xs text-red-400 mt-0.5 max-w-xs truncate">
                          {run.error_message}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {run.current_stage?.replace(/_/g, " ") ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      <span className={run.is_local_ai ? "text-green-700" : "text-blue-700"}>
                        {run.is_local_ai ? "local" : "cloud"}
                      </span>{" "}
                      {run.ai_model ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-gray-600">
                      {run.static_findings_count}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-purple-700">
                      {run.ai_hypotheses_count}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-green-700">
                      {run.validated_findings_count}
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-400 text-xs">
                      {run.commit_sha?.slice(0, 7) ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-gray-500 text-xs">
                      {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-4 py-3">
                      {!terminal.has(run.status) && (
                        <button
                          onClick={() => cancelRun(run.id)}
                          disabled={cancelling === run.id}
                          className="px-2 py-1 rounded text-xs border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-50"
                        >
                          {cancelling === run.id ? "…" : "Cancel"}
                        </button>
                      )}
                      {run.project_id && (
                        <Link
                          href={`/projects/${run.project_id}`}
                          className="ml-2 text-xs text-indigo-600 hover:underline"
                        >
                          Project →
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between text-sm">
            <span className="text-gray-500">Page {currentPage} of {totalPages}</span>
            <div className="flex gap-2">
              <button
                disabled={offset === 0}
                onClick={() => { const o = Math.max(0, offset - limit); setOffset(o); loadData(o); }}
                className="px-3 py-1 rounded border border-gray-200 text-gray-600 disabled:opacity-40 hover:bg-gray-50"
              >
                Previous
              </button>
              <button
                disabled={offset + limit >= total}
                onClick={() => { const o = offset + limit; setOffset(o); loadData(o); }}
                className="px-3 py-1 rounded border border-gray-200 text-gray-600 disabled:opacity-40 hover:bg-gray-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
