"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Finding, FindingSeverity } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";

interface Props {
  analysisId: string;
}

const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_STYLES: Record<FindingSeverity, string> = {
  critical: "bg-red-100 text-red-900 border-red-300",
  high: "bg-orange-100 text-orange-900 border-orange-300",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-300",
  low: "bg-blue-100 text-blue-800 border-blue-300",
  info: "bg-slate-100 text-slate-600 border-slate-300",
};

const SEVERITY_DOT: Record<FindingSeverity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-400",
  info: "bg-slate-400",
};

export default function FindingsPanel({ analysisId }: Props) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("");

  useEffect(() => {
    setLoading(true);
    api.analyses
      .findings(analysisId, severityFilter || undefined)
      .then((resp) => {
        setFindings(resp.items);
        setTotal(resp.total);
      })
      .catch((err) => setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load findings"))
      .finally(() => setLoading(false));
  }, [analysisId, severityFilter]);

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3">
        {error}
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-slate-400">
        <p className="text-sm">
          {severityFilter ? `No ${severityFilter} findings.` : "No code-quality findings."}
        </p>
        <p className="text-xs mt-2">Code-quality results are not security findings and are never verified vulnerabilities.</p>
        {severityFilter && (
          <button onClick={() => setSeverityFilter("")} className="text-xs text-indigo-500 mt-2 hover:underline">
            Clear filter
          </button>
        )}
      </div>
    );
  }

  // Group by severity for display
  const grouped = new Map<FindingSeverity, Finding[]>();
  for (const sev of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length > 0) grouped.set(sev, group);
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-slate-500">
          {total} code-quality finding{total !== 1 ? "s" : ""}
        </p>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="text-xs border border-slate-300 rounded-md px-2 py-1 text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-400"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-4">
        {Array.from(grouped.entries()).map(([sev, items]) => (
          <div key={sev}>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
              {sev} <span className="font-normal text-slate-400">({items.length})</span>
            </h4>
            <div className="space-y-1">
              {items.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  isExpanded={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingRow({
  finding: f,
  isExpanded,
  onToggle,
}: {
  finding: Finding;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const sev = f.severity as FindingSeverity;
  return (
    <div className={`border rounded-lg overflow-hidden ${SEVERITY_STYLES[sev]}`}>
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:brightness-95 transition-all"
      >
        <span className={`mt-1 inline-block w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[sev]}`} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{f.message}</p>
          <p className="text-xs opacity-70 font-mono mt-0.5">
            {f.file_path}:{f.line}
          </p>
        </div>
        <span className="text-xs px-2 py-0.5 rounded border bg-white/70 text-slate-700 shrink-0">CODE QUALITY</span>
        <span className="text-xs opacity-60 shrink-0 capitalize">{f.category.replace(/_/g, " ")}</span>
        <svg
          className={`w-4 h-4 opacity-50 shrink-0 mt-0.5 transition-transform ${isExpanded ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 border-t border-current border-opacity-20 bg-white bg-opacity-60 space-y-3">
          <p className="text-sm text-slate-700 mt-3">{f.explanation}</p>
          {f.evidence && (
            <div>
              <p className="text-xs font-medium text-slate-500 mb-1">Evidence</p>
              <pre className="text-xs bg-slate-900 text-slate-100 rounded p-2 overflow-x-auto">{f.evidence}</pre>
            </div>
          )}
          {f.suggested_fix && (
            <p className="text-xs text-emerald-700 bg-emerald-50 border border-emerald-200 rounded px-3 py-2">
              💡 {f.suggested_fix}
            </p>
          )}
          <div className="flex flex-wrap gap-3 text-xs text-slate-400">
            <span>Confidence: <span className="font-medium text-slate-600">{f.confidence}</span></span>
            <span className="text-xs px-2 py-0.5 rounded border bg-slate-50 text-slate-700">CODE QUALITY</span>
            <span>Analyzer: <span className="font-mono text-slate-600">{f.analyzer}</span></span>
            {f.parser_backend ? (
              <span>Parser: <span className="font-mono text-slate-600">{f.parser_backend}</span></span>
            ) : null}
            <span>Lines: <span className="font-mono text-slate-600">{f.line}–{f.end_line}</span></span>
          </div>
        </div>
      )}
    </div>
  );
}
