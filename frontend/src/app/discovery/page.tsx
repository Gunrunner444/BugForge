"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { DiscoveryRun, DiscoverySettings } from "@/lib/types";

function StatusBadge({ status }: { status: string }) {
  const colours: Record<string, string> = {
    running: "bg-blue-100 text-blue-800",
    completed: "bg-green-100 text-green-800",
    failed: "bg-red-100 text-red-800",
    cancelled: "bg-gray-100 text-gray-700",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${colours[status] ?? "bg-gray-100 text-gray-700"}`}>
      {status}
    </span>
  );
}

export default function DiscoveryPage() {
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [total, setTotal] = useState(0);
  const [settings, setSettings] = useState<DiscoverySettings | null>(null);
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  async function loadData() {
    try {
      const [runsResp, settingsResp] = await Promise.all([
        api.discovery.listRuns(0, 20),
        api.discovery.getSettings(),
      ]);
      setRuns(runsResp.items);
      setTotal(runsResp.total);
      setSettings(settingsResp);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load discovery data");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  async function triggerDiscovery() {
    setTriggering(true);
    setError(null);
    try {
      const run = await api.discovery.triggerRun(5);
      setRuns((prev) => [run, ...prev]);
      setTotal((t) => t + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to trigger discovery");
    } finally {
      setTriggering(false);
    }
  }

  return (
    <div className="max-w-5xl mx-auto py-8 px-4">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Repository Discovery</h1>
          <p className="mt-1 text-sm text-gray-500">
            Automatically discover and screen public GitHub repositories for analysis.
          </p>
        </div>
        <button
          onClick={triggerDiscovery}
          disabled={triggering}
          className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-medium hover:bg-indigo-700 disabled:opacity-50 transition-colors"
        >
          {triggering ? "Starting…" : "Run Discovery Now"}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* Discovery mode banner */}
      {settings && (
        <div className="mb-6 rounded-lg border border-gray-200 bg-gray-50 p-4 text-sm">
          <div className="flex flex-wrap gap-6">
            <span>
              <span className="font-medium text-gray-700">Mode:</span>{" "}
              <span className={settings.discovery_mode === "disabled" ? "text-gray-400" : "text-indigo-700 font-semibold"}>
                {settings.discovery_mode}
              </span>
            </span>
            <span>
              <span className="font-medium text-gray-700">Min stars:</span>{" "}
              {settings.discovery_min_stars.toLocaleString()}
            </span>
            <span>
              <span className="font-medium text-gray-700">Languages:</span>{" "}
              {settings.discovery_languages || "all"}
            </span>
            <span>
              <span className="font-medium text-gray-700">License required:</span>{" "}
              {settings.discovery_require_license ? "yes" : "no"}
            </span>
            <span>
              <span className="font-medium text-gray-700">Max size:</span>{" "}
              {settings.discovery_max_size_kb > 0 ? `${(settings.discovery_max_size_kb / 1024).toFixed(0)} MB` : "unlimited"}
            </span>
          </div>
        </div>
      )}

      {/* Discovery runs table */}
      <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">
            Recent Discovery Runs{total > 0 && ` (${total})`}
          </h2>
          <Link href="/repositories" className="text-xs text-indigo-600 hover:underline">
            View discovered repositories →
          </Link>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-gray-400">Loading…</div>
        ) : runs.length === 0 ? (
          <div className="p-8 text-center text-sm text-gray-400">
            No discovery runs yet. Click &ldquo;Run Discovery Now&rdquo; to start.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-xs font-medium text-gray-500 uppercase">
              <tr>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-right">Discovered</th>
                <th className="px-4 py-3 text-right">Eligible</th>
                <th className="px-4 py-3 text-right">Rejected</th>
                <th className="px-4 py-3 text-right">API Calls</th>
                <th className="px-4 py-3 text-left">Started</th>
                <th className="px-4 py-3 text-right">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {runs.map((run) => (
                <tr key={run.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <StatusBadge status={run.status} />
                    {run.error_message && (
                      <p className="text-xs text-red-500 mt-1 max-w-xs truncate">{run.error_message}</p>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right font-mono">{run.discovered_count}</td>
                  <td className="px-4 py-3 text-right font-mono text-green-700">{run.eligible_count}</td>
                  <td className="px-4 py-3 text-right font-mono text-gray-400">{run.rejected_count}</td>
                  <td className="px-4 py-3 text-right font-mono text-gray-400">{run.github_api_requests}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {new Date(run.started_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right text-gray-500">
                    {run.duration_seconds != null ? `${run.duration_seconds.toFixed(1)}s` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Safety policy summary */}
      {settings && (
        <div className="mt-6 rounded-lg border border-yellow-200 bg-yellow-50 p-4">
          <h3 className="text-sm font-semibold text-yellow-800 mb-2">Safety Policy</h3>
          <div className="grid grid-cols-2 gap-2 text-xs text-yellow-700">
            <span>Skip forks: {settings.discovery_skip_forks ? "✓" : "✗"}</span>
            <span>Skip archived: {settings.discovery_skip_archived ? "✓" : "✗"}</span>
            <span>Docker exec: {settings.safety_allow_docker_exec ? "allowed" : "blocked"}</span>
            <span>Network in sandbox: {settings.safety_allow_sandbox_network ? "allowed" : "blocked"}</span>
            <span>Dep install: {settings.safety_allow_dep_install ? "allowed" : "blocked"}</span>
            <span>Max repo size: {settings.safety_max_repo_size_kb > 0 ? `${(settings.safety_max_repo_size_kb / 1024).toFixed(0)} MB` : "unlimited"}</span>
          </div>
          <p className="mt-2 text-xs text-yellow-600">
            Configure via environment variables (see <code>.env.example</code>). Stars are not a security control.
          </p>
        </div>
      )}
    </div>
  );
}
