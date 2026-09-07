"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { RepositoryCandidate, CandidateStatusCounts } from "@/lib/types";

const ELIGIBILITY_COLOURS: Record<string, string> = {
  discovered: "bg-gray-100 text-gray-600",
  screening: "bg-blue-100 text-blue-700",
  eligible: "bg-green-100 text-green-700",
  rejected: "bg-red-100 text-red-700",
  blocked: "bg-red-200 text-red-900",
  queued: "bg-yellow-100 text-yellow-700",
  analyzing: "bg-blue-200 text-blue-800",
  completed: "bg-emerald-100 text-emerald-700",
  failed: "bg-orange-100 text-orange-700",
};

const SAFETY_COLOURS: Record<string, string> = {
  safe_candidate: "text-green-600",
  low_risk: "text-yellow-600",
  needs_review: "text-orange-600",
  blocked: "text-red-600",
};

function StatusBadge({ status }: { status: string }) {
  const cls = ELIGIBILITY_COLOURS[status] ?? "bg-gray-100 text-gray-700";
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

const STATUS_FILTERS = ["", "eligible", "rejected", "blocked", "completed", "failed"];

export default function RepositoriesPage() {
  const [candidates, setCandidates] = useState<RepositoryCandidate[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState<CandidateStatusCounts | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState<string | null>(null);

  const limit = 50;

  async function loadData(newOffset = 0, newStatus = statusFilter) {
    setLoading(true);
    setError(null);
    try {
      const [listResp, countsResp] = await Promise.all([
        api.candidates.list(newStatus || undefined, newOffset, limit),
        api.candidates.counts(),
      ]);
      setCandidates(listResp.items);
      setTotal(listResp.total);
      setCounts(countsResp);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load repositories");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleFilterChange(s: string) {
    setStatusFilter(s);
    setOffset(0);
    loadData(0, s);
  }

  async function triggerAnalysis(candidateId: string) {
    setAnalyzing(candidateId);
    try {
      await api.candidates.analyze(candidateId);
      await loadData(offset, statusFilter);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to trigger analysis");
    } finally {
      setAnalyzing(null);
    }
  }

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="max-w-6xl mx-auto py-8 px-4">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Discovered Repositories</h1>
          <p className="mt-1 text-sm text-gray-500">
            Public GitHub repositories found by the discovery system.
          </p>
        </div>
        <Link
          href="/discovery"
          className="px-4 py-2 rounded-lg border border-gray-300 text-sm text-gray-700 hover:bg-gray-50 transition-colors"
        >
          Configure Discovery
        </Link>
      </div>

      {error && (
        <div className="mb-4 rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Status counts summary */}
      {counts && (
        <div className="mb-6 flex flex-wrap gap-3">
          {Object.entries(counts.counts)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([s, n]) => (
              <button
                key={s}
                onClick={() => handleFilterChange(statusFilter === s ? "" : s)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                  statusFilter === s
                    ? "border-indigo-500 bg-indigo-50 text-indigo-700"
                    : "border-gray-200 bg-white text-gray-600 hover:border-gray-300"
                }`}
              >
                {s} <span className="font-mono ml-1">{n}</span>
              </button>
            ))}
          {statusFilter && (
            <button
              onClick={() => handleFilterChange("")}
              className="px-3 py-1.5 rounded-full text-xs font-medium border border-gray-200 text-gray-400 hover:text-gray-600"
            >
              Clear filter
            </button>
          )}
        </div>
      )}

      <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-100 text-sm text-gray-500">
          {total} repositor{total === 1 ? "y" : "ies"}
          {statusFilter ? ` with status "${statusFilter}"` : ""}
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-gray-400">Loading…</div>
        ) : candidates.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-400">
            No repositories found.{" "}
            <Link href="/discovery" className="text-indigo-600 hover:underline">
              Run a discovery sweep
            </Link>{" "}
            to populate this list.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-xs font-medium text-gray-500 uppercase">
              <tr>
                <th className="px-4 py-3 text-left">Repository</th>
                <th className="px-4 py-3 text-left">Language</th>
                <th className="px-4 py-3 text-right">Stars</th>
                <th className="px-4 py-3 text-left">Eligibility</th>
                <th className="px-4 py-3 text-left">Safety</th>
                <th className="px-4 py-3 text-left">Analysis</th>
                <th className="px-4 py-3 text-left">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {candidates.map((c) => (
                <tr key={c.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <a
                      href={c.html_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-medium text-indigo-700 hover:underline"
                    >
                      {c.full_name}
                    </a>
                    {c.description && (
                      <p className="text-xs text-gray-400 mt-0.5 max-w-xs truncate">
                        {c.description}
                      </p>
                    )}
                    {c.rejection_reason && (
                      <p className="text-xs text-red-400 mt-0.5 max-w-xs truncate">
                        {c.rejection_reason}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-500">{c.primary_language ?? "—"}</td>
                  <td className="px-4 py-3 text-right font-mono">{c.stars.toLocaleString()}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={c.eligibility_status} />
                    {c.eligibility_score != null && (
                      <span className="ml-1 text-xs text-gray-400">
                        {(c.eligibility_score * 100).toFixed(0)}%
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {c.safety_classification ? (
                      <span className={`text-xs font-medium ${SAFETY_COLOURS[c.safety_classification] ?? "text-gray-500"}`}>
                        {c.safety_classification.replace(/_/g, " ")}
                      </span>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {c.analysis_status ? (
                      <span className="text-xs text-gray-500">{c.analysis_status}</span>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                    {c.last_analyzed_commit && (
                      <span className="ml-1 text-xs font-mono text-gray-300">
                        {c.last_analyzed_commit.slice(0, 7)}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {c.eligibility_status === "eligible" && (
                      <button
                        onClick={() => triggerAnalysis(c.id)}
                        disabled={analyzing === c.id}
                        className="px-3 py-1 rounded text-xs bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"
                      >
                        {analyzing === c.id ? "…" : "Analyze"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between text-sm">
            <span className="text-gray-500">
              Page {currentPage} of {totalPages}
            </span>
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
