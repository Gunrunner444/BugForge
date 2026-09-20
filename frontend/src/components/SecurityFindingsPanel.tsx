"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { SecurityFinding } from "@/lib/types";
import LoadingSpinner from "@/components/ui/LoadingSpinner";

interface Props {
  projectId: string;
}

const STATUS_STYLES: Record<string, string> = {
  potential: "bg-amber-100 text-amber-900 border-amber-300",
  corroborated: "bg-orange-100 text-orange-900 border-orange-300",
  reproduced: "bg-yellow-100 text-yellow-900 border-yellow-300",
  verified: "bg-red-100 text-red-900 border-red-300",
  human_accepted: "bg-emerald-100 text-emerald-900 border-emerald-300",
  rejected: "bg-slate-100 text-slate-600 border-slate-300",
};

export default function SecurityFindingsPanel({ projectId }: Props) {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    api.security
      .findings(projectId)
      .then((resp) => {
        setFindings(resp.items);
        setTotal(resp.total);
      })
      .catch((err) => setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to load"))
      .finally(() => setLoading(false));
  }, [projectId]);

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner />
      </div>
    );
  }

  if (error) {
    return <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3">{error}</div>;
  }

  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-slate-400">
        <p className="text-sm">No potential security findings from static analysis.</p>
        <p className="text-xs mt-2">These are hypotheses, not verified vulnerabilities.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">
        {total} potential/corroborated finding{total === 1 ? "" : "s"}. None are verified in this phase.
      </p>
      {findings.map((finding) => (
        <button
          key={finding.id}
          type="button"
          onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
          className="w-full text-left rounded-lg border border-slate-200 p-3 hover:bg-slate-50"
        >
          <div className="flex items-center gap-2">
            <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_STYLES[finding.status] ?? STATUS_STYLES.potential}`}>
              {finding.status}
            </span>
            <span className="text-xs text-slate-500">{finding.evidence_tier}</span>
            <span className="text-sm font-medium text-slate-800 truncate">{finding.title}</span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            {finding.vulnerability_class} {finding.file_path}
            {finding.line != null ? `:${finding.line}` : ""}
          </p>
          {expanded === finding.id && (
            <div className="mt-2 text-xs text-slate-600 space-y-1">
              {finding.hypothesis && <p>{finding.hypothesis}</p>}
              {finding.ai_analysis && <p className="italic">{finding.ai_analysis}</p>}
              {finding.rule_ids && <p>Rules: {finding.rule_ids}</p>}
            </div>
          )}
        </button>
      ))}
    </div>
  );
}
