"use client";

import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { TestResult, TestRun } from "@/lib/types";
import { formatDate, statusColor } from "@/lib/utils";
import LoadingSpinner from "@/components/ui/LoadingSpinner";

interface Props {
  projectId: string;
}

const POLL_INTERVAL_MS = 2000;

export default function TestRunPanel({ projectId }: Props) {
  const [runs, setRuns] = useState<TestRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<TestRun | null>(null);
  const [results, setResults] = useState<TestResult[]>([]);
  const [loadingResults, setLoadingResults] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadRuns = async () => {
    try {
      const resp = await api.projects.testRuns(projectId);
      setRuns(resp.items);
      if (resp.items.length > 0 && selectedRun === null) {
        setSelectedRun(resp.items[0]);
      }
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load test runs");
    }
  };

  const loadResults = async (runId: string) => {
    setLoadingResults(true);
    try {
      const resp = await api.testRuns.results(runId);
      setResults(resp.items);
    } catch {
      setResults([]);
    } finally {
      setLoadingResults(false);
    }
  };

  useEffect(() => {
    loadRuns();
  }, [projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (selectedRun?.status === "completed" || selectedRun?.status === "failed") {
      loadResults(selectedRun.id);
    } else {
      setResults([]);
    }
  }, [selectedRun?.id, selectedRun?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll while a run is in-progress
  useEffect(() => {
    const active = runs.some((r) => r.status === "pending" || r.status === "running");
    if (!active) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    pollRef.current = setInterval(async () => {
      try {
        const resp = await api.projects.testRuns(projectId);
        setRuns(resp.items);
        if (resp.items.length > 0) {
          const latest = resp.items[0];
          setSelectedRun(latest);
          const stillActive = resp.items.some((r) => r.status === "pending" || r.status === "running");
          if (!stillActive && pollRef.current) {
            clearInterval(pollRef.current);
          }
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    }, POLL_INTERVAL_MS);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [runs, projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRunTests = async () => {
    setError(null);
    setStarting(true);
    try {
      const run = await api.projects.runTests(projectId);
      setRuns((prev) => [run, ...prev]);
      setSelectedRun(run);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start test run");
    } finally {
      setStarting(false);
    }
  };

  const isRunning = runs.some((r) => r.status === "pending" || r.status === "running");

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-slate-800">Test Runs</h2>
        <button
          onClick={handleRunTests}
          disabled={starting || isRunning}
          className="px-4 py-2 text-sm font-medium bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 disabled:opacity-50 transition-colors"
        >
          {starting || isRunning ? "Running…" : "Run Tests"}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3 mb-4">
          {error}
        </div>
      )}

      {runs.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {runs.map((r) => (
            <button
              key={r.id}
              onClick={() => setSelectedRun(r)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                selectedRun?.id === r.id
                  ? "border-emerald-400 bg-emerald-50 text-emerald-700"
                  : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
              }`}
            >
              {formatDate(r.created_at)}
            </button>
          ))}
        </div>
      )}

      {selectedRun && (
        <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
          {/* Summary bar */}
          <div className="flex flex-wrap items-center gap-4 px-6 py-4 border-b border-slate-100">
            <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${statusColor(selectedRun.status)}`}>
              {selectedRun.status}
            </span>
            {selectedRun.duration_seconds != null && (
              <span className="text-xs text-slate-400">
                {selectedRun.duration_seconds.toFixed(2)}s
              </span>
            )}
            {selectedRun.status === "completed" && (
              <div className="flex gap-3 text-sm">
                <Stat label="Total" value={selectedRun.total_tests} />
                <Stat label="Passed" value={selectedRun.passed} color="text-emerald-600" />
                {selectedRun.failed > 0 && (
                  <Stat label="Failed" value={selectedRun.failed} color="text-red-600" />
                )}
                {selectedRun.skipped > 0 && (
                  <Stat label="Skipped" value={selectedRun.skipped} color="text-amber-600" />
                )}
                {selectedRun.errors > 0 && (
                  <Stat label="Errors" value={selectedRun.errors} color="text-orange-600" />
                )}
              </div>
            )}
            {selectedRun.exit_code != null && (
              <span className="text-xs text-slate-400 ml-auto">
                exit&nbsp;{selectedRun.exit_code}
              </span>
            )}
          </div>

          {selectedRun.error_message && (
            <div className="px-6 py-3 bg-red-50 text-red-700 text-sm border-b border-red-100">
              {selectedRun.error_message}
            </div>
          )}

          {(selectedRun.status === "pending" || selectedRun.status === "running") && (
            <div className="flex flex-col items-center py-12 gap-3 text-slate-400">
              <LoadingSpinner />
              <p className="text-sm">Running tests…</p>
            </div>
          )}

          {selectedRun.status === "completed" && (
            <div className="p-6">
              {loadingResults ? (
                <div className="flex justify-center py-8"><LoadingSpinner /></div>
              ) : results.length === 0 ? (
                <p className="text-slate-400 text-sm">No individual test results available.</p>
              ) : (
                <TestResultTable results={results} />
              )}
            </div>
          )}
        </div>
      )}

      {runs.length === 0 && !isRunning && (
        <div className="text-center py-12 border border-dashed border-slate-200 rounded-xl text-slate-400">
          <p className="text-sm">No test runs yet. Click <strong>Run Tests</strong> to start.</p>
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  color = "text-slate-700",
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <span className="text-xs">
      <span className={`font-semibold ${color}`}>{value}</span>
      <span className="text-slate-400 ml-1">{label}</span>
    </span>
  );
}

function TestResultTable({ results }: { results: TestResult[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div className="space-y-1">
      {results.map((r) => (
        <div key={r.id} className="border border-slate-100 rounded-lg overflow-hidden">
          <button
            onClick={() => setExpanded(expanded === r.id ? null : r.id)}
            className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-slate-50 transition-colors"
          >
            <StatusDot status={r.status} />
            <span className="font-mono text-xs text-slate-700 flex-1 truncate" title={r.node_id}>
              {r.node_id}
            </span>
            {r.duration_seconds != null && (
              <span className="text-xs text-slate-400 ml-auto mr-2 shrink-0">
                {r.duration_seconds < 1
                  ? `${(r.duration_seconds * 1000).toFixed(0)}ms`
                  : `${r.duration_seconds.toFixed(2)}s`}
              </span>
            )}
            <svg
              className={`w-4 h-4 text-slate-400 shrink-0 transition-transform ${expanded === r.id ? "rotate-180" : ""}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {expanded === r.id && (
            <div className="px-4 pb-4 border-t border-slate-100 bg-slate-50">
              {r.traceback && (
                <div className="mt-3">
                  <p className="text-xs font-medium text-slate-500 mb-1">Traceback</p>
                  <pre className="text-xs bg-white border border-slate-200 rounded p-3 overflow-x-auto text-red-700 whitespace-pre-wrap">
                    {r.traceback}
                  </pre>
                </div>
              )}
              {r.skip_reason && (
                <p className="mt-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                  {r.skip_reason}
                </p>
              )}
              {!r.traceback && !r.skip_reason && (
                <p className="mt-2 text-xs text-slate-400">No additional details.</p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function StatusDot({ status }: { status: TestResult["status"] }) {
  const colors: Record<string, string> = {
    passed: "bg-emerald-500",
    failed: "bg-red-500",
    skipped: "bg-amber-400",
    error: "bg-orange-500",
    timeout: "bg-purple-500",
  };
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full shrink-0 ${colors[status] ?? "bg-slate-400"}`}
      title={status}
    />
  );
}
