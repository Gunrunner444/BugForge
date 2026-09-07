"use client";

import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { PatchCandidate, RepairSession } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { formatDate } from "@/lib/utils";

interface Props {
  projectId: string;
}

const DISPOSITION_STYLES: Record<string, { badge: string; label: string }> = {
  best: { badge: "bg-emerald-100 text-emerald-800", label: "Best candidate ✓" },
  accepted: { badge: "bg-green-100 text-green-700", label: "Accepted" },
  rejected: { badge: "bg-red-100 text-red-700", label: "Rejected" },
  pending: { badge: "bg-slate-100 text-slate-600", label: "Pending" },
};

const STATUS_STYLES: Record<string, string> = {
  completed: "text-green-600",
  running: "text-blue-600",
  failed: "text-red-600",
  pending: "text-slate-500",
};

function CandidateCard({ candidate }: { candidate: PatchCandidate }) {
  const [showDiff, setShowDiff] = useState(false);
  const disp = DISPOSITION_STYLES[candidate.disposition] ?? DISPOSITION_STYLES.pending;

  return (
    <div className="border border-slate-200 rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-700">
            Candidate #{candidate.rank}
          </span>
          <span
            className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${disp.badge}`}
          >
            {disp.label}
          </span>
          {candidate.score !== null && (
            <span className="text-xs text-slate-500">
              Score: {(candidate.score * 100).toFixed(0)}%
            </span>
          )}
        </div>
        <span className="text-xs text-slate-400">{candidate.status}</span>
      </div>

      {candidate.patch_plan && (
        <p className="text-sm text-slate-600">{candidate.patch_plan}</p>
      )}

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-1">
          <span className="text-slate-500">Bug fixed:</span>
          <span
            className={
              candidate.bug_fixed === true
                ? "text-green-600 font-medium"
                : candidate.bug_fixed === false
                  ? "text-red-600"
                  : "text-slate-400"
            }
          >
            {candidate.bug_fixed === true
              ? "Yes ✓"
              : candidate.bug_fixed === false
                ? "No ✗"
                : "Unknown"}
          </span>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-slate-500">Regressions:</span>
          <span
            className={
              candidate.no_regressions === true
                ? "text-green-600"
                : candidate.regression_count > 0
                  ? "text-red-600"
                  : "text-slate-400"
            }
          >
            {candidate.no_regressions === true
              ? "None ✓"
              : candidate.regression_count > 0
                ? `${candidate.regression_count} new`
                : "Unknown"}
          </span>
        </div>
        {candidate.existing_tests_total !== null && (
          <div className="flex items-center gap-1 col-span-2">
            <span className="text-slate-500">Tests:</span>
            <span className="text-slate-700">
              {candidate.existing_tests_passed ?? 0}/{candidate.existing_tests_total} passed
              {(candidate.existing_tests_failed ?? 0) > 0 && (
                <span className="text-red-600 ml-1">
                  ({candidate.existing_tests_failed} failed)
                </span>
              )}
            </span>
          </div>
        )}
        {candidate.changed_files.length > 0 && (
          <div className="col-span-2">
            <span className="text-slate-500">Changed files: </span>
            <span className="text-slate-700">{candidate.changed_files.join(", ")}</span>
          </div>
        )}
      </div>

      {candidate.validation_error && (
        <p className="text-xs text-red-600 bg-red-50 rounded px-2 py-1">
          Validation error: {candidate.validation_error}
        </p>
      )}

      {candidate.patch_diff && (
        <div>
          <button
            onClick={() => setShowDiff((v) => !v)}
            className="text-xs text-blue-600 hover:underline"
          >
            {showDiff ? "Hide diff" : "Show diff"}
          </button>
          {showDiff && (
            <pre className="mt-2 text-xs bg-slate-900 text-slate-100 rounded p-3 overflow-x-auto max-h-64 overflow-y-auto whitespace-pre">
              {candidate.patch_diff}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function RepairPanel({ projectId }: Props) {
  const [sessions, setSessions] = useState<RepairSession[]>([]);
  const [selected, setSelected] = useState<RepairSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadSessions = async () => {
    try {
      const resp = await api.projects.repairSessions(projectId);
      setSessions(resp.items);
      if (resp.items.length > 0 && !selected) setSelected(resp.items[0]);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load repair sessions");
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (id: string) => {
    try {
      const detail = await api.repair.get(id);
      setSelected(detail);
    } catch {
      /* keep previous */
    }
  };

  useEffect(() => {
    loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => {
    const active = sessions.some((s) => s.status === "pending" || s.status === "running");
    if (!active) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      if (selected && (selected.status === "pending" || selected.status === "running")) {
        await loadDetail(selected.id);
      }
      await loadSessions();
    }, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions, selected]);

  const startRepair = async () => {
    setStarting(true);
    setError(null);
    try {
      const session = await api.projects.startRepair(projectId, { max_candidates: 1 });
      setSessions((prev) => [session, ...prev]);
      setSelected(session);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start repair");
    } finally {
      setStarting(false);
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-800">Automated Repair</h2>
        <button
          onClick={startRepair}
          disabled={starting}
          className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {starting ? <LoadingSpinner size={16} /> : null}
          {starting ? "Starting…" : "Start Repair"}
        </button>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 p-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {sessions.length === 0 ? (
        <p className="text-sm text-slate-500">
          No repair sessions yet. Click &ldquo;Start Repair&rdquo; to generate an automated patch.
        </p>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Session list */}
          <div className="space-y-2">
            {sessions.map((s) => (
              <button
                key={s.id}
                onClick={() => {
                  setSelected(s);
                  loadDetail(s.id);
                }}
                className={`w-full text-left rounded-lg border p-3 transition-colors ${
                  selected?.id === s.id
                    ? "border-blue-300 bg-blue-50"
                    : "border-slate-200 hover:bg-slate-50"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span
                    className={`text-xs font-medium ${STATUS_STYLES[s.status] ?? "text-slate-500"}`}
                  >
                    {s.status.charAt(0).toUpperCase() + s.status.slice(1)}
                  </span>
                  <span className="text-xs text-slate-400">
                    {s.total_candidates} candidate{s.total_candidates !== 1 ? "s" : ""}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-500">{formatDate(s.created_at)}</p>
              </button>
            ))}
          </div>

          {/* Session detail */}
          {selected && (
            <div className="lg:col-span-2 space-y-4">
              <div className="rounded-lg border border-slate-200 p-4 space-y-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`text-sm font-semibold ${STATUS_STYLES[selected.status] ?? ""}`}
                  >
                    {selected.status.charAt(0).toUpperCase() + selected.status.slice(1)}
                  </span>
                  {(selected.status === "pending" || selected.status === "running") && (
                    <LoadingSpinner size={16} />
                  )}
                </div>

                {selected.error_message && (
                  <p className="text-sm text-red-600">{selected.error_message}</p>
                )}

                <div className="text-xs text-slate-500 space-y-0.5">
                  <p>Started: {selected.started_at ? formatDate(selected.started_at) : "—"}</p>
                  <p>
                    Completed:{" "}
                    {selected.completed_at ? formatDate(selected.completed_at) : "—"}
                  </p>
                </div>

                {selected.best_candidate_id && (
                  <p className="text-xs text-emerald-600 font-medium">
                    Best patch candidate identified ✓
                  </p>
                )}
              </div>

              {selected.candidates && selected.candidates.length > 0 ? (
                <div className="space-y-3">
                  <h3 className="text-sm font-medium text-slate-700">
                    Patch Candidates ({selected.candidates.length})
                  </h3>
                  {selected.candidates.map((c) => (
                    <CandidateCard key={c.id} candidate={c} />
                  ))}
                </div>
              ) : selected.status === "completed" ? (
                <p className="text-sm text-slate-500">No patch candidates generated.</p>
              ) : null}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
