"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { PatchCandidate, PatchVerification, VerificationDecision } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import { formatDate } from "@/lib/utils";

interface Props {
  sessionId: string;
  candidate: PatchCandidate;
}

const TERMINAL_STATES: Set<string> = new Set([
  "verified", "rejected", "inconclusive", "environment_failed", "baseline_failed",
]);

const DECISION_STYLES: Record<string, { badge: string; label: string }> = {
  verified: { badge: "bg-emerald-100 text-emerald-800 border border-emerald-300", label: "Verified" },
  rejected: { badge: "bg-red-100 text-red-700 border border-red-300", label: "Rejected" },
  inconclusive: { badge: "bg-amber-100 text-amber-800 border border-amber-300", label: "Inconclusive" },
  environment_failed: { badge: "bg-slate-100 text-slate-600 border border-slate-300", label: "Environment Failed" },
  baseline_failed: { badge: "bg-orange-100 text-orange-700 border border-orange-300", label: "Baseline Failed" },
};

function ReproBadge({ value, label }: { value: boolean | null; label: string }) {
  const color =
    value === true ? "text-green-600" : value === false ? "text-red-600" : "text-slate-400";
  const icon = value === true ? "✓" : value === false ? "✗" : "?";
  return (
    <span className="flex items-center gap-1 text-xs">
      <span className="text-slate-500">{label}:</span>
      <span className={`font-medium ${color}`}>
        {value === true ? "Yes" : value === false ? "No" : "Unknown"} {icon}
      </span>
    </span>
  );
}

function TestCompareRow({
  label,
  baseline,
  post,
}: {
  label: string;
  baseline: number;
  post: number;
}) {
  const delta = post - baseline;
  return (
    <tr className="text-xs">
      <td className="py-0.5 pr-3 text-slate-500">{label}</td>
      <td className="py-0.5 pr-3 text-slate-700 text-right">{baseline}</td>
      <td className="py-0.5 pr-3 text-slate-700 text-right">{post}</td>
      <td
        className={`py-0.5 text-right font-medium ${
          delta > 0 && label === "Passed"
            ? "text-green-600"
            : delta < 0 && label === "Passed"
              ? "text-red-600"
              : delta > 0 && label !== "Passed"
                ? "text-red-600"
                : delta < 0 && label !== "Passed"
                  ? "text-green-600"
                  : "text-slate-400"
        }`}
      >
        {delta > 0 ? `+${delta}` : delta === 0 ? "—" : delta}
      </td>
    </tr>
  );
}

function VerificationDetail({ v }: { v: PatchVerification }) {
  const [showEvidence, setShowEvidence] = useState(false);
  const decisionStyle =
    DECISION_STYLES[v.verification_decision ?? ""] ?? DECISION_STYLES.inconclusive;

  return (
    <div className="space-y-4 text-sm">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <span
          className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-semibold ${decisionStyle.badge}`}
        >
          {decisionStyle.label}
        </span>
        {v.verification_score !== null && (
          <span className="text-slate-500 text-xs">
            Score: <span className="font-medium text-slate-700">{(v.verification_score * 100).toFixed(0)}%</span>
          </span>
        )}
        <span className="text-xs text-slate-400">{v.status}</span>
      </div>

      {/* Reproduction comparison */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded border border-slate-200 p-3 space-y-1">
          <p className="text-xs font-medium text-slate-600 uppercase tracking-wide mb-2">Before patch</p>
          <ReproBadge value={v.baseline_reproduced} label="Bug reproduced" />
          <p className="text-xs text-slate-500">
            Tests: {v.baseline_tests_passed}/{v.baseline_tests_total} passed,{" "}
            {v.baseline_tests_failed + v.baseline_tests_error} failed
          </p>
          <p className="text-xs text-slate-500">
            Static findings: {v.baseline_static_findings}
          </p>
        </div>
        <div className="rounded border border-slate-200 p-3 space-y-1">
          <p className="text-xs font-medium text-slate-600 uppercase tracking-wide mb-2">After patch</p>
          <ReproBadge value={v.post_patch_reproduced} label="Bug reproduced" />
          <p className="text-xs text-slate-500">
            Tests: {v.post_tests_passed}/{v.post_tests_total} passed,{" "}
            {v.post_tests_failed + v.post_tests_error} failed
          </p>
          <p className="text-xs text-slate-500">
            Static findings: {v.post_static_findings}
          </p>
        </div>
      </div>

      {/* Comparison table */}
      {(v.baseline_tests_total > 0 || v.post_tests_total > 0) && (
        <div className="rounded border border-slate-200 p-3">
          <p className="text-xs font-medium text-slate-600 uppercase tracking-wide mb-2">Test comparison</p>
          <table className="w-full">
            <thead>
              <tr className="text-xs text-slate-400">
                <th className="text-left font-normal pr-3"></th>
                <th className="text-right font-normal pr-3">Before</th>
                <th className="text-right font-normal pr-3">After</th>
                <th className="text-right font-normal">Delta</th>
              </tr>
            </thead>
            <tbody>
              <TestCompareRow label="Total" baseline={v.baseline_tests_total} post={v.post_tests_total} />
              <TestCompareRow label="Passed" baseline={v.baseline_tests_passed} post={v.post_tests_passed} />
              <TestCompareRow label="Failed" baseline={v.baseline_tests_failed} post={v.post_tests_failed} />
            </tbody>
          </table>
          {v.regression_count > 0 && (
            <p className="mt-2 text-xs text-red-600 font-medium">
              {v.regression_count} newly failing test(s)
            </p>
          )}
          {v.newly_failing_ids.length > 0 && (
            <ul className="mt-1 space-y-0.5">
              {v.newly_failing_ids.slice(0, 5).map((id) => (
                <li key={id} className="text-xs text-red-500 font-mono truncate">
                  {id}
                </li>
              ))}
              {v.newly_failing_ids.length > 5 && (
                <li className="text-xs text-slate-400">… and {v.newly_failing_ids.length - 5} more</li>
              )}
            </ul>
          )}
        </div>
      )}

      {/* Security */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-slate-500">Security:</span>
        <span className={v.security_passed === true ? "text-green-600 font-medium" : v.security_passed === false ? "text-red-600 font-medium" : "text-slate-400"}>
          {v.security_passed === true ? "Passed ✓" : v.security_passed === false ? "Failed ✗" : "Unknown"}
        </span>
        {v.security_issues.length > 0 && (
          <span className="text-red-500">{v.security_issues.join("; ")}</span>
        )}
      </div>

      {/* Decision reasons */}
      {v.decision_reasons.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-slate-600">Decision basis:</p>
          <ul className="space-y-0.5">
            {v.decision_reasons.map((r, i) => (
              <li key={i} className="text-xs text-slate-600 flex items-start gap-1">
                <span className="text-slate-400 mt-0.5">•</span>
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Evidence summary (collapsible) */}
      {v.evidence_summary && (
        <div>
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="text-xs text-blue-600 hover:underline"
          >
            {showEvidence ? "Hide" : "Show"} full evidence summary
          </button>
          {showEvidence && (
            <pre className="mt-2 text-xs bg-slate-50 rounded p-3 overflow-auto whitespace-pre-wrap border border-slate-200">
              {v.evidence_summary}
            </pre>
          )}
        </div>
      )}

      {v.error_message && (
        <p className="text-xs text-red-600 bg-red-50 rounded p-2 border border-red-200">
          {v.error_message}
        </p>
      )}

      {v.completed_at && (
        <p className="text-xs text-slate-400">Completed: {formatDate(v.completed_at)}</p>
      )}
    </div>
  );
}

export default function VerificationPanel({ sessionId, candidate }: Props) {
  const [verification, setVerification] = useState<PatchVerification | null>(null);
  const [loading, setLoading] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const fetchVerification = useCallback(async () => {
    try {
      const v = await api.repair.getVerification(sessionId, candidate.id);
      setVerification(v);
      if (TERMINAL_STATES.has(v.status)) {
        stopPolling();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        // Not started yet — that's fine
      } else {
        setError(String(e));
        stopPolling();
      }
    }
  }, [sessionId, candidate.id, stopPolling]);

  // Initial load
  useEffect(() => {
    setLoading(true);
    fetchVerification().finally(() => setLoading(false));
    return stopPolling;
  }, [fetchVerification, stopPolling]);

  // Start polling when running
  useEffect(() => {
    if (verification && !TERMINAL_STATES.has(verification.status)) {
      stopPolling();
      pollRef.current = setInterval(fetchVerification, 3000);
    } else {
      stopPolling();
    }
    return stopPolling;
  }, [verification?.status, fetchVerification, stopPolling]); // eslint-disable-line

  const handleStartVerification = async () => {
    setStarting(true);
    setError(null);
    try {
      const v = await api.repair.startVerification(sessionId, candidate.id);
      setVerification(v);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-sm text-slate-500 py-2">
        <LoadingSpinner size={16} />
        <span>Loading verification…</span>
      </div>
    );
  }

  if (!verification) {
    return (
      <div className="space-y-2">
        <p className="text-xs text-slate-500">
          No verification has been run for this candidate yet.
        </p>
        {error && <p className="text-xs text-red-600">{error}</p>}
        <button
          onClick={handleStartVerification}
          disabled={starting}
          className="inline-flex items-center gap-2 rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {starting && <LoadingSpinner size={16} />}
          {starting ? "Starting…" : "Run Patch Verification"}
        </button>
      </div>
    );
  }

  if (!TERMINAL_STATES.has(verification.status)) {
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-sm text-blue-600">
          <LoadingSpinner size={16} />
          <span>Verification running… ({verification.status})</span>
        </div>
      </div>
    );
  }

  return <VerificationDetail v={verification} />;
}
