"use client";

import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { BugReproductionAttempt, BugReproductionSession } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { formatDate } from "@/lib/utils";

interface Props {
  projectId: string;
}

const CLASSIFICATION_STYLES: Record<string, { badge: string; label: string }> = {
  consistently_reproduced: { badge: "bg-red-100 text-red-800", label: "Consistently reproduced ✓" },
  reproduced: { badge: "bg-orange-100 text-orange-800", label: "Reproduced" },
  intermittent: { badge: "bg-amber-100 text-amber-800", label: "Intermittent" },
  inconclusive: { badge: "bg-slate-100 text-slate-600", label: "Inconclusive" },
  not_reproduced: { badge: "bg-emerald-100 text-emerald-700", label: "Not reproduced" },
};

export default function ReproductionPanel({ projectId }: Props) {
  const [sessions, setSessions] = useState<BugReproductionSession[]>([]);
  const [selected, setSelected] = useState<BugReproductionSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedAttempt, setExpandedAttempt] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadSessions = async () => {
    try {
      const resp = await api.projects.reproductionSessions(projectId);
      setSessions(resp.items);
      if (resp.items.length > 0 && !selected) setSelected(resp.items[0]);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (id: string) => {
    try {
      const detail = await api.reproduction.get(id);
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
    pollRef.current = setInterval(async () => {
      const resp = await api.projects.reproductionSessions(projectId).catch(() => null);
      if (!resp) { if (pollRef.current) clearInterval(pollRef.current); return; }
      setSessions(resp.items);
      const stillActive = resp.items.some((s) => s.status === "pending" || s.status === "running");
      if (!stillActive) {
        if (pollRef.current) clearInterval(pollRef.current);
        setStarting(false);
        if (resp.items[0]) await loadDetail(resp.items[0].id);
      } else if (resp.items[0]) {
        setSelected(resp.items[0]);
      }
    }, 2500);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions, projectId]);

  const handleStart = async () => {
    setError(null);
    setStarting(true);
    try {
      const s = await api.projects.reproduce(projectId);
      setSessions((prev) => [s, ...prev]);
      setSelected(s);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start");
      setStarting(false);
    }
  };

  const isRunning = sessions.some((s) => s.status === "pending" || s.status === "running");

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Bug Reproduction</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Runs reproducer code multiple times to verify whether a bug can be reliably triggered
          </p>
        </div>
        <button
          onClick={handleStart}
          disabled={starting || isRunning}
          className="px-4 py-2 text-sm font-medium bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:opacity-50 transition-colors"
        >
          {starting || isRunning ? "Reproducing…" : "Start Reproduction"}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3 mb-4">{error}</div>
      )}

      {loading && <div className="flex justify-center py-10"><LoadingSpinner /></div>}

      {!loading && sessions.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {sessions.map((s) => (
            <button
              key={s.id}
              onClick={() => loadDetail(s.id)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                selected?.id === s.id
                  ? "border-rose-400 bg-rose-50 text-rose-700"
                  : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
              }`}
            >
              {formatDate(s.created_at)}
            </button>
          ))}
        </div>
      )}

      {selected && <SessionDetail session={selected} expandedAttempt={expandedAttempt} onToggle={(id) => setExpandedAttempt(expandedAttempt === id ? null : id)} />}

      {!loading && sessions.length === 0 && (
        <div className="text-center py-12 border border-dashed border-slate-200 rounded-xl text-slate-400">
          <p className="text-sm mb-2">No reproduction sessions yet.</p>
          <p className="text-xs">Run an analysis and AI debugging first, then click <strong>Start Reproduction</strong>.</p>
        </div>
      )}
    </div>
  );
}

function SessionDetail({
  session: s,
  expandedAttempt,
  onToggle,
}: {
  session: BugReproductionSession;
  expandedAttempt: string | null;
  onToggle: (id: string) => void;
}) {
  const cls = s.final_classification ? CLASSIFICATION_STYLES[s.final_classification] : null;

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 px-6 py-4 border-b border-slate-100">
        <StatusBadge status={s.status} />
        {s.reproducibility_rate != null && (
          <span className="text-sm font-semibold">
            {s.successful_attempts}/{s.attempt_count} reproduced
          </span>
        )}
        {cls && (
          <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${cls.badge}`}>
            {cls.label}
          </span>
        )}
        {s.error_message && (
          <span className="text-xs text-red-600 ml-auto truncate max-w-xs">{s.error_message}</span>
        )}
      </div>

      {(s.status === "pending" || s.status === "running") && (
        <div className="flex flex-col items-center py-12 gap-3 text-slate-400">
          <LoadingSpinner />
          <p className="text-sm">Running reproduction attempts…</p>
        </div>
      )}

      {s.status === "completed" && (s.attempts ?? []).length === 0 && (
        <div className="px-6 py-8 text-center text-slate-400 text-sm">No attempt data available.</div>
      )}

      {(s.attempts ?? []).length > 0 && (
        <div className="p-6 space-y-2">
          <p className="text-xs text-slate-500 mb-3">
            Attempts — clearly distinguishes{" "}
            <strong>AI hypothesis</strong> from{" "}
            <strong>executable evidence</strong>
          </p>
          {(s.attempts ?? []).map((a) => (
            <AttemptRow
              key={a.id}
              attempt={a}
              isExpanded={expandedAttempt === a.id}
              onToggle={() => onToggle(a.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function AttemptRow({
  attempt: a,
  isExpanded,
  onToggle,
}: {
  attempt: BugReproductionAttempt;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const icon = a.reproduced ? "🔴" : a.classification === "timeout" ? "⏱" : "⚪";
  const color = a.reproduced ? "border-red-200 bg-red-50" : "border-slate-100 bg-white";

  return (
    <div className={`border rounded-lg overflow-hidden ${color}`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:brightness-95 transition-all"
      >
        <span>{icon}</span>
        <span className="text-sm font-medium">Attempt {a.attempt_number}</span>
        <span className={`ml-2 text-xs px-2 py-0.5 rounded-full ${a.reproduced ? "bg-red-100 text-red-700" : "bg-slate-100 text-slate-600"}`}>
          {a.classification}
        </span>
        {a.duration_seconds != null && (
          <span className="text-xs text-slate-400 ml-auto">{a.duration_seconds.toFixed(2)}s</span>
        )}
        <svg className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 border-t border-slate-100 space-y-3 bg-white">
          {a.reproducer_code && (
            <div className="mt-3">
              <p className="text-xs font-medium text-slate-500 mb-1">Reproducer code (AI-generated)</p>
              <pre className="text-xs bg-slate-900 text-slate-100 rounded p-3 overflow-x-auto whitespace-pre-wrap max-h-48">{a.reproducer_code}</pre>
            </div>
          )}
          {(a.stdout || a.stderr) && (
            <div>
              <p className="text-xs font-medium text-slate-500 mb-1">Output</p>
              <pre className="text-xs bg-slate-50 border border-slate-200 rounded p-2 overflow-x-auto max-h-32">
                {(a.stdout ?? "") + (a.stderr ?? "")}
              </pre>
            </div>
          )}
          {a.exit_code != null && (
            <p className="text-xs text-slate-400">Exit code: <code>{a.exit_code}</code></p>
          )}
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: BugReproductionSession["status"] }) {
  const styles: Record<string, string> = {
    pending: "bg-yellow-100 text-yellow-800",
    running: "bg-blue-100 text-blue-800",
    completed: "bg-emerald-100 text-emerald-800",
    failed: "bg-red-100 text-red-800",
  };
  return <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${styles[status] ?? styles.failed}`}>{status}</span>;
}
