"use client";

import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { DebuggingHypothesis, DebuggingSession, TestRun } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { formatDate } from "@/lib/utils";

interface Props {
  projectId: string;
  latestTestRun?: TestRun | null;
  latestAnalysisId?: string | null;
}

const CONFIDENCE_STYLES: Record<string, string> = {
  confirmed: "border-emerald-400 bg-emerald-50 text-emerald-800",
  highly_likely: "border-blue-400 bg-blue-50 text-blue-800",
  likely: "border-indigo-300 bg-indigo-50 text-indigo-800",
  possible: "border-yellow-300 bg-yellow-50 text-yellow-800",
  insufficient_evidence: "border-slate-300 bg-slate-50 text-slate-600",
};

const CONFIDENCE_BADGE: Record<string, string> = {
  confirmed: "bg-emerald-100 text-emerald-800",
  highly_likely: "bg-blue-100 text-blue-800",
  likely: "bg-indigo-100 text-indigo-800",
  possible: "bg-yellow-100 text-yellow-800",
  insufficient_evidence: "bg-slate-100 text-slate-600",
};

export default function DebuggingPanel({ projectId, latestTestRun, latestAnalysisId }: Props) {
  const [sessions, setSessions] = useState<DebuggingSession[]>([]);
  const [selected, setSelected] = useState<DebuggingSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedHyp, setExpandedHyp] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadSessions = async () => {
    try {
      const resp = await api.projects.debugSessions(projectId);
      setSessions(resp.items);
      if (resp.items.length > 0 && selected === null) {
        const latest = resp.items[0];
        setSelected(latest);
        if (latest.status === "completed") {
          const detail = await api.debugging.get(latest.id);
          setSelected(detail);
        }
      }
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId]);

  // Poll while a session is in-progress
  useEffect(() => {
    const active = sessions.some((s) => s.status === "pending" || s.status === "running");
    if (!active) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }

    pollRef.current = setInterval(async () => {
      try {
        const resp = await api.projects.debugSessions(projectId);
        setSessions(resp.items);
        if (resp.items.length > 0) {
          const latest = resp.items[0];
          const stillActive = resp.items.some(
            (s) => s.status === "pending" || s.status === "running"
          );
          if (!stillActive) {
            if (pollRef.current) clearInterval(pollRef.current);
            setStarting(false);
            const detail = await api.debugging.get(latest.id);
            setSelected(detail);
          } else {
            setSelected(latest);
          }
        }
      } catch {
        if (pollRef.current) clearInterval(pollRef.current);
        setStarting(false);
      }
    }, 2500);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions, projectId]);

  const handleStartSession = async () => {
    setError(null);
    setStarting(true);
    try {
      const session = await api.projects.debug(
        projectId,
        latestAnalysisId ?? undefined,
        latestTestRun?.id ?? undefined
      );
      setSessions((prev) => [session, ...prev]);
      setSelected(session);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start session");
      setStarting(false);
    }
  };

  const isRunning = sessions.some((s) => s.status === "pending" || s.status === "running");

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">AI Debugging</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Evidence-first analysis — AI hypotheses are labeled separately from tool output
          </p>
        </div>
        <button
          onClick={handleStartSession}
          disabled={starting || isRunning}
          className="px-4 py-2 text-sm font-medium bg-violet-600 text-white rounded-lg hover:bg-violet-700 disabled:opacity-50 transition-colors"
        >
          {starting || isRunning ? "Analyzing…" : "Start Debugging"}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3 mb-4">
          {error}
        </div>
      )}

      {loading && (
        <div className="flex justify-center py-10">
          <LoadingSpinner />
        </div>
      )}

      {!loading && sessions.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={async () => {
                const detail = await api.debugging.get(s.id).catch(() => s);
                setSelected(detail);
              }}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                selected?.id === s.id
                  ? "border-violet-400 bg-violet-50 text-violet-700"
                  : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
              }`}
            >
              {formatDate(s.created_at)}
            </button>
          ))}
        </div>
      )}

      {selected && (
        <SessionDetail
          session={selected}
          expandedHyp={expandedHyp}
          onToggleHyp={(id) => setExpandedHyp(expandedHyp === id ? null : id)}
        />
      )}

      {!loading && sessions.length === 0 && (
        <div className="text-center py-12 border border-dashed border-slate-200 rounded-xl text-slate-400">
          <p className="text-sm mb-2">No debugging sessions yet.</p>
          <p className="text-xs">
            Run an analysis and test suite first, then click{" "}
            <strong>Start Debugging</strong> to collect evidence and generate AI hypotheses.
          </p>
        </div>
      )}
    </div>
  );
}

function SessionDetail({
  session,
  expandedHyp,
  onToggleHyp,
}: {
  session: DebuggingSession;
  expandedHyp: string | null;
  onToggleHyp: (id: string) => void;
}) {
  const hypotheses = session.hypotheses ?? [];
  const aiCalls = session.ai_calls ?? [];

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
      {/* Status bar */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-100">
        <StatusBadge status={session.status} />
        {session.completed_at && session.started_at && (
          <span className="text-xs text-slate-400">
            {((new Date(session.completed_at).getTime() - new Date(session.started_at).getTime()) / 1000).toFixed(1)}s
          </span>
        )}
        {aiCalls.length > 0 && (
          <span className="text-xs text-slate-400 ml-auto">
            {aiCalls[0].provider}/{aiCalls[0].model} ·{" "}
            {aiCalls[0].prompt_tokens + aiCalls[0].completion_tokens} tokens
          </span>
        )}
      </div>

      {session.error_message && (
        <div className="px-6 py-3 bg-red-50 text-red-700 text-sm border-b border-red-100">
          {session.error_message}
        </div>
      )}

      {(session.status === "pending" || session.status === "running") && (
        <div className="flex flex-col items-center py-12 gap-3 text-slate-400">
          <LoadingSpinner />
          <p className="text-sm">Collecting evidence and querying AI provider…</p>
        </div>
      )}

      {session.status === "completed" && hypotheses.length === 0 && (
        <div className="px-6 py-8 text-center text-slate-400 text-sm">
          No hypotheses generated. Check if there are failing tests and run an analysis first.
        </div>
      )}

      {hypotheses.length > 0 && (
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-medium text-slate-700">
              {hypotheses.length} hypothesis{hypotheses.length !== 1 ? "es" : ""}
            </span>
            <span className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-full px-2 py-0.5">
              ⚠ AI inference — not verified by execution
            </span>
          </div>

          {hypotheses.map((h, idx) => (
            <HypothesisCard
              key={h.id}
              hypothesis={h}
              index={idx + 1}
              isExpanded={expandedHyp === h.id}
              onToggle={() => onToggleHyp(h.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function HypothesisCard({
  hypothesis: h,
  index,
  isExpanded,
  onToggle,
}: {
  hypothesis: DebuggingHypothesis;
  index: number;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const borderStyle = CONFIDENCE_STYLES[h.confidence_label] ?? CONFIDENCE_STYLES.possible;
  const badgeStyle = CONFIDENCE_BADGE[h.confidence_label] ?? CONFIDENCE_BADGE.possible;

  return (
    <div className={`border rounded-xl overflow-hidden ${borderStyle}`}>
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-5 py-4 text-left hover:brightness-95 transition-all"
      >
        <span className="text-xs font-bold opacity-50 shrink-0 mt-0.5">#{index}</span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold leading-snug">{h.root_cause}</p>
          {h.affected_files.length > 0 && (
            <p className="text-xs opacity-60 font-mono mt-1 truncate">
              {h.affected_files.slice(0, 3).join(", ")}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${badgeStyle}`}>
            {h.confidence_label.replace(/_/g, " ")}
          </span>
          <span className="text-xs opacity-50">{Math.round(h.confidence * 100)}%</span>
          <svg
            className={`w-4 h-4 opacity-40 transition-transform ${isExpanded ? "rotate-180" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {isExpanded && (
        <div className="px-5 pb-5 border-t border-current border-opacity-20 bg-white bg-opacity-70 space-y-4">
          <p className="text-sm text-slate-700 mt-4 leading-relaxed">{h.explanation}</p>

          {h.evidence_summary.length > 0 && (
            <Section label="🔍 Evidence (from BugForge tools)">
              <ul className="space-y-1">
                {h.evidence_summary.map((e, i) => (
                  <li key={i} className="text-xs text-slate-700 flex gap-2">
                    <span className="text-slate-400 shrink-0">•</span>
                    <span>{e}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {h.contradictory_evidence.length > 0 && (
            <Section label="⚡ Contradictory evidence">
              <ul className="space-y-1">
                {h.contradictory_evidence.map((e, i) => (
                  <li key={i} className="text-xs text-slate-600 flex gap-2">
                    <span className="text-slate-400 shrink-0">•</span>
                    <span>{e}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {h.reproduction_strategy && (
            <Section label="🔁 Reproduction strategy (AI suggestion)">
              <p className="text-xs text-slate-700">{h.reproduction_strategy}</p>
            </Section>
          )}

          {h.recommended_tests.length > 0 && (
            <Section label="🧪 Recommended tests (AI suggestion)">
              {h.recommended_tests.map((t, i) => (
                <code key={i} className="block text-xs font-mono bg-slate-800 text-slate-100 rounded px-2 py-1 mt-1">
                  {t}
                </code>
              ))}
            </Section>
          )}

          <p className="text-xs text-slate-400 border-t border-slate-100 pt-3 mt-2">
            Provider: <span className="font-mono">{h.ai_provider}/{h.ai_model}</span>
          </p>
        </div>
      )}
    </div>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs font-semibold text-slate-500 mb-1">{label}</p>
      {children}
    </div>
  );
}

function StatusBadge({ status }: { status: DebuggingSession["status"] }) {
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
