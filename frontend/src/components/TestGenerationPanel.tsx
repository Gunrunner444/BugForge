"use client";

import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { GeneratedTest, TestGenerationSession } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { formatDate } from "@/lib/utils";

interface Props {
  projectId: string;
  latestAnalysisId?: string | null;
  latestTestRunId?: string | null;
  latestDebugSessionId?: string | null;
}

const CATEGORY_COLORS: Record<string, string> = {
  edge_case: "bg-purple-100 text-purple-700",
  boundary: "bg-blue-100 text-blue-700",
  invalid_input: "bg-orange-100 text-orange-700",
  error_handling: "bg-red-100 text-red-700",
  regression: "bg-amber-100 text-amber-700",
  behavioral: "bg-green-100 text-green-700",
  integration: "bg-sky-100 text-sky-700",
  security: "bg-rose-100 text-rose-700",
};

const EXECUTION_COLORS: Record<string, string> = {
  passed: "text-emerald-700",
  failed: "text-red-600",
  error: "text-orange-600",
  timeout: "text-amber-600",
  not_run: "text-slate-400",
  pending: "text-slate-400",
};

export default function TestGenerationPanel({
  projectId,
  latestAnalysisId,
  latestTestRunId,
  latestDebugSessionId,
}: Props) {
  const [sessions, setSessions] = useState<TestGenerationSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<TestGenerationSession | null>(null);
  const [tests, setTests] = useState<GeneratedTest[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadSessions = async () => {
    try {
      const resp = await api.projects.testGenSessions(projectId);
      setSessions(resp.items);
      if (resp.items.length > 0 && !selectedSession) {
        setSelectedSession(resp.items[0]);
      }
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  };

  const loadTests = async (sessionId: string) => {
    try {
      const resp = await api.testGeneration.tests(sessionId);
      setTests(resp.items);
    } catch {
      setTests([]);
    }
  };

  useEffect(() => {
    loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  useEffect(() => {
    if (selectedSession?.status === "completed") {
      loadTests(selectedSession.id);
    } else {
      setTests([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedSession?.id, selectedSession?.status]);

  // Poll while generating
  useEffect(() => {
    const active = sessions.some((s) => s.status === "pending" || s.status === "running");
    if (!active) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    pollRef.current = setInterval(async () => {
      try {
        const resp = await api.projects.testGenSessions(projectId);
        setSessions(resp.items);
        const latest = resp.items[0];
        if (latest) setSelectedSession(latest);
        const stillActive = resp.items.some((s) => s.status === "pending" || s.status === "running");
        if (!stillActive) {
          if (pollRef.current) clearInterval(pollRef.current);
          setGenerating(false);
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current);
        setGenerating(false);
      }
    }, 2500);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions, projectId]);

  const handleGenerate = async () => {
    setError(null);
    setGenerating(true);
    try {
      const session = await api.projects.generateTests(projectId, {
        analysis_id: latestAnalysisId ?? undefined,
        test_run_id: latestTestRunId ?? undefined,
        debugging_session_id: latestDebugSessionId ?? undefined,
      });
      setSessions((prev) => [session, ...prev]);
      setSelectedSession(session);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start generation");
      setGenerating(false);
    }
  };

  const isRunning = sessions.some((s) => s.status === "pending" || s.status === "running");

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Test Generation</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            AI-generated test candidates — not applied to repository automatically
          </p>
        </div>
        <button
          onClick={handleGenerate}
          disabled={generating || isRunning}
          className="px-4 py-2 text-sm font-medium bg-teal-600 text-white rounded-lg hover:bg-teal-700 disabled:opacity-50 transition-colors"
        >
          {generating || isRunning ? "Generating…" : "Generate Tests"}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3 mb-4">
          {error}
        </div>
      )}

      {loading && <div className="flex justify-center py-10"><LoadingSpinner /></div>}

      {!loading && sessions.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={() => setSelectedSession(s)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                selectedSession?.id === s.id
                  ? "border-teal-400 bg-teal-50 text-teal-700"
                  : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
              }`}
            >
              {formatDate(s.created_at)} · {s.candidate_count} candidates
            </button>
          ))}
        </div>
      )}

      {selectedSession && (
        <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
          <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-100">
            <StatusBadge status={selectedSession.status} />
            <span className="text-xs text-slate-400">
              {selectedSession.candidate_count} candidate{selectedSession.candidate_count !== 1 ? "s" : ""}
            </span>
            {selectedSession.error_message && (
              <span className="text-xs text-red-600 ml-auto truncate max-w-xs">
                {selectedSession.error_message}
              </span>
            )}
          </div>

          {(selectedSession.status === "pending" || selectedSession.status === "running") && (
            <div className="flex flex-col items-center py-12 gap-3 text-slate-400">
              <LoadingSpinner />
              <p className="text-sm">Generating test candidates…</p>
            </div>
          )}

          {selectedSession.status === "completed" && tests.length === 0 && (
            <div className="px-6 py-8 text-center text-slate-400 text-sm">
              No test candidates were generated. Try running an analysis and test suite first.
            </div>
          )}

          {tests.length > 0 && (
            <div className="p-6 space-y-3">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-full px-2 py-0.5">
                  ⚠ AI-generated code — not applied to repository
                </span>
              </div>
              {tests.map((t) => (
                <TestCard
                  key={t.id}
                  test={t}
                  isExpanded={expanded === t.id}
                  onToggle={() => setExpanded(expanded === t.id ? null : t.id)}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {!loading && sessions.length === 0 && (
        <div className="text-center py-12 border border-dashed border-slate-200 rounded-xl text-slate-400">
          <p className="text-sm mb-2">No test generation sessions yet.</p>
          <p className="text-xs">Run an analysis first, then click <strong>Generate Tests</strong>.</p>
        </div>
      )}
    </div>
  );
}

function TestCard({
  test: t,
  isExpanded,
  onToggle,
}: {
  test: GeneratedTest;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const categoryStyle = CATEGORY_COLORS[t.category] ?? "bg-slate-100 text-slate-600";
  const execColor = EXECUTION_COLORS[t.execution_status] ?? "text-slate-400";

  return (
    <div className="border border-slate-200 rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-slate-50 transition-colors"
      >
        <ExecutionDot status={t.execution_status} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-800 truncate" title={t.target_symbol}>
            {t.target_symbol}
          </p>
          <p className="text-xs text-slate-500 truncate font-mono">{t.target_file}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-xs px-2 py-0.5 rounded-full ${categoryStyle}`}>
            {t.category.replace(/_/g, " ")}
          </span>
          {t.quality_score != null && (
            <span className="text-xs text-slate-400">
              q:{Math.round(t.quality_score * 100)}%
            </span>
          )}
          <span className={`text-xs font-medium ${execColor}`}>{t.execution_status}</span>
          <svg
            className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? "rotate-180" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 border-t border-slate-100 bg-slate-50 space-y-3">
          <p className="text-sm text-slate-600 mt-3">{t.rationale}</p>

          {t.validation_status === "invalid" && t.validation_error && (
            <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded px-3 py-2">
              Validation failed: {t.validation_error}
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs font-medium text-slate-500">Generated code</p>
              <span className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-1.5 py-0.5">
                AI-generated · not applied
              </span>
            </div>
            <pre className="text-xs bg-slate-900 text-slate-100 rounded p-3 overflow-x-auto whitespace-pre-wrap">
              {t.generated_code}
            </pre>
          </div>

          {t.execution_output && (
            <div>
              <p className="text-xs font-medium text-slate-500 mb-1">Execution output</p>
              <pre className="text-xs bg-white border border-slate-200 rounded p-2 overflow-x-auto max-h-40">
                {t.execution_output}
              </pre>
            </div>
          )}

          {t.quality_notes && (
            <p className="text-xs text-slate-500">Quality notes: {t.quality_notes}</p>
          )}
        </div>
      )}
    </div>
  );
}

function ExecutionDot({ status }: { status: GeneratedTest["execution_status"] }) {
  const colors: Record<string, string> = {
    passed: "bg-emerald-500",
    failed: "bg-red-500",
    error: "bg-orange-500",
    timeout: "bg-amber-400",
    not_run: "bg-slate-300",
    pending: "bg-slate-300",
  };
  return (
    <span className={`mt-1.5 inline-block w-2 h-2 rounded-full shrink-0 ${colors[status] ?? "bg-slate-300"}`} />
  );
}

function StatusBadge({ status }: { status: TestGenerationSession["status"] }) {
  const styles: Record<string, string> = {
    pending: "bg-yellow-100 text-yellow-800",
    running: "bg-blue-100 text-blue-800",
    completed: "bg-emerald-100 text-emerald-800",
    failed: "bg-red-100 text-red-800",
  };
  return (
    <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${styles[status] ?? styles.failed}`}>
      {status}
    </span>
  );
}
