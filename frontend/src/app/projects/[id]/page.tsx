"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import type { Analysis, Project } from "@/lib/types";
import AnalysisResults from "@/components/AnalysisResults";
import LoadingSpinner from "@/components/ui/LoadingSpinner";
import Badge from "@/components/ui/Badge";
import { formatDate, statusColor } from "@/lib/utils";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();

  const [project, setProject] = useState<Project | null>(null);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"overview" | "files" | "entities" | "imports">("overview");

  const loadProject = useCallback(async () => {
    try {
      const [proj, analysisResp] = await Promise.all([
        api.projects.get(id),
        api.projects.analyses(id),
      ]);
      setProject(proj);
      setAnalyses(analysisResp.items);
      if (analysisResp.items.length > 0 && !selectedAnalysis) {
        setSelectedAnalysis(analysisResp.items[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [id, selectedAnalysis]);

  useEffect(() => {
    loadProject();
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll while an analysis is running
  useEffect(() => {
    const running = analyses.some((a) => a.status === "pending" || a.status === "running");
    if (!running) return;

    const timer = setInterval(async () => {
      try {
        const resp = await api.projects.analyses(id);
        setAnalyses(resp.items);
        if (resp.items.length > 0) {
          const latest = resp.items[0];
          setSelectedAnalysis(latest);
          if (latest.status === "completed" || latest.status === "failed") {
            clearInterval(timer);
            setAnalyzing(false);
          }
        }
      } catch {
        clearInterval(timer);
      }
    }, 2000);

    return () => clearInterval(timer);
  }, [analyses, id]);

  const handleAnalyze = async () => {
    if (!project) return;
    setAnalyzing(true);
    setError(null);
    try {
      const analysis = await api.projects.analyze(id);
      setAnalyses((prev) => [analysis, ...prev]);
      setSelectedAnalysis(analysis);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setAnalyzing(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-20">
        <LoadingSpinner />
      </div>
    );
  }

  if (error && !project) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-800 rounded-lg p-4 text-sm">
        {error}
      </div>
    );
  }

  if (!project) return null;

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">{project.name}</h1>
          {project.description && (
            <p className="text-slate-500 mt-1 text-sm">{project.description}</p>
          )}
          <p className="text-xs text-slate-400 font-mono mt-2">{project.repository_path}</p>
        </div>
        <button
          onClick={handleAnalyze}
          disabled={analyzing}
          className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
        >
          {analyzing ? "Analyzing…" : "Run Analysis"}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-800 text-sm rounded-lg p-3 mb-4">
          {error}
        </div>
      )}

      {/* Analysis list */}
      {analyses.length > 0 && (
        <div className="mb-6">
          <h2 className="text-sm font-medium text-slate-500 mb-2">Analyses</h2>
          <div className="flex flex-wrap gap-2">
            {analyses.map((a) => (
              <button
                key={a.id}
                onClick={() => { setSelectedAnalysis(a); setTab("overview"); }}
                className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                  selectedAnalysis?.id === a.id
                    ? "border-indigo-400 bg-indigo-50 text-indigo-700"
                    : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                }`}
              >
                {formatDate(a.created_at)}
                {" · "}
                <Badge status={a.status as any} />
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Analysis detail */}
      {selectedAnalysis && (
        <AnalysisResults
          analysis={selectedAnalysis}
          tab={tab}
          onTabChange={setTab}
        />
      )}

      {!selectedAnalysis && analyses.length === 0 && (
        <div className="text-center py-16 border border-dashed border-slate-200 rounded-xl text-slate-400">
          No analyses yet. Click <strong>Run Analysis</strong> to start.
        </div>
      )}
    </div>
  );
}
