"use client";

import { useEffect, useState } from "react";
import type { Analysis, CodeEntity, ImportRecord, RepositoryFile } from "@/lib/types";
import { api } from "@/lib/api";
import FindingsPanel from "@/components/FindingsPanel";
import SecurityFindingsPanel from "@/components/SecurityFindingsPanel";
import { formatDate, languageColor, statusColor } from "@/lib/utils";
import LoadingSpinner from "@/components/ui/LoadingSpinner";

type Tab = "overview" | "files" | "entities" | "imports" | "findings" | "security";

interface Props {
  analysis: Analysis;
  tab: Tab;
  onTabChange: (tab: Tab) => void;
}

const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "files", label: "Files" },
  { key: "entities", label: "Entities" },
  { key: "imports", label: "Imports" },
  { key: "findings", label: "Code Quality" },
  { key: "security", label: "Security" },
];

export default function AnalysisResults({ analysis, tab, onTabChange }: Props) {
  const [files, setFiles] = useState<RepositoryFile[]>([]);
  const [entities, setEntities] = useState<CodeEntity[]>([]);
  const [imports, setImports] = useState<ImportRecord[]>([]);
  const [loadingTab, setLoadingTab] = useState(false);

  useEffect(() => {
    if (analysis.status !== "completed") return;
    if (tab === "files" && files.length === 0) {
      setLoadingTab(true);
      api.analyses.files(analysis.id).then((r) => setFiles(r.items)).finally(() => setLoadingTab(false));
    }
    if (tab === "entities" && entities.length === 0) {
      setLoadingTab(true);
      api.analyses.entities(analysis.id).then((r) => setEntities(r.items)).finally(() => setLoadingTab(false));
    }
    if (tab === "imports" && imports.length === 0) {
      setLoadingTab(true);
      api.analyses.imports(analysis.id).then((r) => setImports(r.items)).finally(() => setLoadingTab(false));
    }
  }, [tab, analysis.id, analysis.status]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm">
      {/* Status bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
        <div className="flex items-center gap-3">
          <span
            className={`text-xs font-medium px-2.5 py-1 rounded-full ${statusColor(analysis.status)}`}
          >
            {analysis.status}
          </span>
          <span className="text-xs text-slate-400">{formatDate(analysis.created_at)}</span>
          {analysis.summary?.analysis_duration_seconds != null && (
            <span className="text-xs text-slate-400">
              {analysis.summary.analysis_duration_seconds.toFixed(2)}s
            </span>
          )}
        </div>
        {analysis.error_message && (
          <span className="text-xs text-red-600 max-w-sm truncate" title={analysis.error_message}>
            {analysis.error_message}
          </span>
        )}
      </div>

      {/* Tabs */}
      {analysis.status === "completed" && (
        <>
          <div className="flex border-b border-slate-100 px-6">
            {TABS.map(({ key, label }) => (
              <button
                key={key}
                onClick={() => onTabChange(key)}
                className={`py-3 px-4 text-sm font-medium border-b-2 transition-colors ${
                  tab === key
                    ? "border-indigo-500 text-indigo-600"
                    : "border-transparent text-slate-500 hover:text-slate-700"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="p-6">
            {loadingTab ? (
              <div className="flex justify-center py-10">
                <LoadingSpinner />
              </div>
            ) : (
              <>
                {tab === "overview" && analysis.summary && (
                  <OverviewTab analysis={analysis} />
                )}
                {tab === "files" && <FilesTab files={files} />}
                {tab === "entities" && <EntitiesTab entities={entities} />}
                {tab === "imports" && <ImportsTab imports={imports} />}
                {tab === "findings" && <FindingsPanel analysisId={analysis.id} />}
                {tab === "security" && <SecurityFindingsPanel projectId={analysis.project_id} />}
              </>
            )}
          </div>
        </>
      )}

      {(analysis.status === "pending" || analysis.status === "running") && (
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-400">
          <LoadingSpinner />
          <p className="text-sm">Analysis in progress…</p>
        </div>
      )}
    </div>
  );
}

function OverviewTab({ analysis }: { analysis: Analysis }) {
  const s = analysis.summary!;
  return (
    <div className="space-y-6">
      {/* Stats grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Total files", value: s.total_files },
          { label: "Source files", value: s.source_files },
          { label: "Test files", value: s.test_files },
          { label: "Code entities", value: s.total_entities },
          { label: "Potential security", value: s.security_findings ?? 0 },
        ].map(({ label, value }) => (
          <div key={label} className="bg-slate-50 rounded-lg p-4 text-center">
            <p className="text-2xl font-bold text-slate-900">{value}</p>
            <p className="text-xs text-slate-500 mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Languages */}
      {s.languages.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-slate-700 mb-3">Languages</h3>
          <div className="flex flex-wrap gap-2">
            {s.languages.map((lang) => (
              <span
                key={lang.language}
                className={`text-xs px-2.5 py-1 rounded-full font-medium ${languageColor(lang.language)}`}
              >
                {lang.language} ({lang.file_count} · {lang.percentage}%)
              </span>
            ))}
          </div>
        </div>
      )}

      {s.language_capabilities && s.language_capabilities.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-slate-700 mb-3">Parser backends</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-100">
                  <th className="pb-2 pr-4 font-medium">Language</th>
                  <th className="pb-2 pr-4 font-medium">Tier</th>
                  <th className="pb-2 pr-4 font-medium">Backend</th>
                  <th className="pb-2 font-medium">Capabilities</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {s.language_capabilities
                  .filter((row) => row.parser_tier !== "detection_only")
                  .map((row) => (
                    <tr key={row.language}>
                      <td className="py-2 pr-4 font-medium text-slate-800">{row.language}</td>
                      <td className="py-2 pr-4">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${tierColor(row.parser_tier)}`}>
                          {tierLabel(row.parser_tier)}
                        </span>
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs text-slate-600">{row.parser_backend}</td>
                      <td className="py-2 text-xs text-slate-500">{row.capabilities.join(", ")}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Frameworks */}
      {s.frameworks.length > 0 && (
        <div>
          <h3 className="text-sm font-medium text-slate-700 mb-3">Detected Frameworks</h3>
          <div className="space-y-2">
            {s.frameworks.map((fw) => (
              <div
                key={fw.name}
                className="flex items-center justify-between bg-slate-50 rounded-lg px-4 py-3"
              >
                <div>
                  <span className="text-sm font-medium text-slate-800">{fw.name}</span>
                  <span className="text-xs text-slate-500 ml-2">{fw.language}</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex flex-wrap gap-1">
                    {fw.evidence.map((e) => (
                      <code key={e} className="text-xs bg-white border border-slate-200 rounded px-1.5 py-0.5">
                        {e}
                      </code>
                    ))}
                  </div>
                  <span className="text-xs text-slate-400">
                    {Math.round(fw.confidence * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FilesTab({ files }: { files: RepositoryFile[] }) {
  if (files.length === 0) return <p className="text-slate-400 text-sm">No files.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-slate-500 border-b border-slate-100">
            <th className="pb-2 pr-4 font-medium">Path</th>
            <th className="pb-2 pr-4 font-medium">Type</th>
            <th className="pb-2 pr-4 font-medium">Language</th>
            <th className="pb-2 pr-4 font-medium">Parser</th>
            <th className="pb-2 pr-4 font-medium text-right">Lines</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-50">
          {files.map((f) => (
            <tr key={f.id} className="hover:bg-slate-50">
              <td className="py-2 pr-4 font-mono text-xs text-slate-700">{f.relative_path}</td>
              <td className="py-2 pr-4">
                <span className={`text-xs px-2 py-0.5 rounded-full ${fileTypeColor(f.file_type)}`}>
                  {f.file_type}
                </span>
              </td>
              <td className="py-2 pr-4">
                {f.language && (
                  <span className={`text-xs px-2 py-0.5 rounded-full ${languageColor(f.language)}`}>
                    {f.language}
                  </span>
                )}
              </td>
              <td className="py-2 pr-4 text-xs text-slate-500">
                {f.parser_tier ? (
                  <span className={`px-2 py-0.5 rounded-full ${tierColor(f.parser_tier)}`}>
                    {tierLabel(f.parser_tier)}
                  </span>
                ) : (
                  "—"
                )}
                {f.has_errors ? <span className="ml-2 text-amber-700">errors</span> : null}
              </td>
              <td className="py-2 pr-4 text-right text-slate-500">{f.line_count || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EntitiesTab({ entities }: { entities: CodeEntity[] }) {
  if (entities.length === 0) return <p className="text-slate-400 text-sm">No entities found.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-slate-500 border-b border-slate-100">
            <th className="pb-2 pr-4 font-medium">Qualified name</th>
            <th className="pb-2 pr-4 font-medium">Type</th>
            <th className="pb-2 pr-4 font-medium text-right">Lines</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-50">
          {entities.map((e) => (
            <tr key={e.id} className="hover:bg-slate-50">
              <td className="py-2 pr-4 font-mono text-xs text-slate-800">{e.qualified_name}</td>
              <td className="py-2 pr-4">
                <span className={`text-xs px-2 py-0.5 rounded-full ${entityTypeColor(e.entity_type)}`}>
                  {e.entity_type}
                </span>
              </td>
              <td className="py-2 pr-4 text-right text-slate-500 text-xs">
                {e.start_line}–{e.end_line}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ImportsTab({ imports }: { imports: ImportRecord[] }) {
  if (imports.length === 0) return <p className="text-slate-400 text-sm">No imports found.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-slate-500 border-b border-slate-100">
            <th className="pb-2 pr-4 font-medium">Module</th>
            <th className="pb-2 pr-4 font-medium">Name</th>
            <th className="pb-2 pr-4 font-medium">Type</th>
            <th className="pb-2 font-medium text-right">Line</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-50">
          {imports.map((imp) => (
            <tr key={imp.id} className="hover:bg-slate-50">
              <td className="py-2 pr-4 font-mono text-xs text-slate-700">{imp.module_name || "."}</td>
              <td className="py-2 pr-4 font-mono text-xs text-slate-500">{imp.imported_name ?? ""}</td>
              <td className="py-2 pr-4">
                <span className={`text-xs px-2 py-0.5 rounded-full ${importTypeColor(imp.import_type)}`}>
                  {imp.import_type}
                </span>
              </td>
              <td className="py-2 text-right text-slate-400 text-xs">{imp.line_number}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const fileTypeColor = (t: string) =>
  ({ source: "bg-blue-50 text-blue-700", test: "bg-green-50 text-green-700", config: "bg-amber-50 text-amber-700", other: "bg-slate-100 text-slate-600" }[t] ?? "bg-slate-100 text-slate-600");

const entityTypeColor = (t: string): string => {
  if (t === "class") return "bg-purple-50 text-purple-700";
  if (t.includes("async")) return "bg-teal-50 text-teal-700";
  if (t === "method") return "bg-indigo-50 text-indigo-700";
  return "bg-blue-50 text-blue-700";
};

const importTypeColor = (t: string): string => {
  if (t === "stdlib") return "bg-slate-100 text-slate-600";
  if (t === "third_party") return "bg-orange-50 text-orange-700";
  if (t === "relative") return "bg-sky-50 text-sky-700";
  return "bg-green-50 text-green-700";
};

const tierLabel = (tier: string): string => {
  if (tier === "full_ast") return "FULL AST";
  if (tier === "profile_fallback") return "PROFILE FALLBACK";
  if (tier === "specialized") return "SPECIALIZED";
  return "DETECTION ONLY";
};

const tierColor = (tier: string): string => {
  if (tier === "full_ast") return "bg-emerald-50 text-emerald-800";
  if (tier === "specialized") return "bg-sky-50 text-sky-800";
  if (tier === "profile_fallback") return "bg-amber-50 text-amber-800";
  return "bg-slate-100 text-slate-600";
};
