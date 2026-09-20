"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";

export default function ResearchWorkbenchPage() {
  const [projectId, setProjectId] = useState("lab");
  const [target, setTarget] = useState("http://127.0.0.1/health");
  const [mode, setMode] = useState("lab");
  const [strategy, setStrategy] = useState("passive_recon");
  const [sessionId, setSessionId] = useState("");
  const [dashboard, setDashboard] = useState<Record<string, unknown> | null>(null);
  const [timeline, setTimeline] = useState<Array<Record<string, unknown>>>([]);
  const [findings, setFindings] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [operatorToken, setOperatorToken] = useState("");

  function rememberToken() {
    if (typeof window !== "undefined" && operatorToken) {
      sessionStorage.setItem("bugforge_operator_token", operatorToken);
    }
  }

  async function createAndStart() {
    setBusy(true);
    setError(null);
    rememberToken();
    try {
      await api.research.createProject({
        name: "Workbench project",
        project_id: projectId,
        target,
        mode,
        strategy,
      });
      const created = await api.research.createSession({
        project_id: projectId,
        target,
        mode,
        thinking: true,
      });
      const id = String(created.id);
      setSessionId(id);
      await api.research.override(id, { action: "change_strategy", strategy });
      const dash = await api.research.dashboard(id);
      setDashboard(dash);
      const events = await api.research.timeline(id);
      setTimeline(Array.isArray(events.items) ? (events.items as Array<Record<string, unknown>>) : []);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start research");
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    if (!sessionId) return;
    setBusy(true);
    try {
      setDashboard(await api.research.dashboard(sessionId));
      const events = await api.research.timeline(sessionId);
      setTimeline(Array.isArray(events.items) ? (events.items as Array<Record<string, unknown>>) : []);
      const found = await api.research.findings(sessionId);
      setFindings(Array.isArray(found.items) ? (found.items as Array<Record<string, unknown>>) : []);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Refresh failed");
    } finally {
      setBusy(false);
    }
  }

  async function control(action: string) {
    if (!sessionId) return;
    setBusy(true);
    try {
      await api.research.override(sessionId, { action });
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Control failed");
      setBusy(false);
    }
  }

  async function step() {
    if (!sessionId) return;
    setBusy(true);
    try {
      await api.research.step(sessionId);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Step failed");
      setBusy(false);
    }
  }

  const sessionKind = String(dashboard?.session_kind || mode.toUpperCase());
  const executionMode = String(dashboard?.execution_mode || "DRY-RUN");

  return (
    <main className="max-w-6xl mx-auto p-6 space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-900">Security Research Workbench</h1>
        <p className="text-sm text-slate-600 mt-1">
          Guided research. ScopeGuard, SafetyController, and human review remain authoritative.
          The AI cannot verify findings, grant approvals, or submit reports.
        </p>
      </header>

      <section className="grid gap-3 md:grid-cols-2 bg-white border border-slate-200 rounded-lg p-4">
        <label className="text-sm">
          Operator token
          <input
            className="mt-1 w-full border rounded px-2 py-1"
            value={operatorToken}
            onChange={(event) => setOperatorToken(event.target.value)}
            type="password"
          />
        </label>
        <label className="text-sm">
          Project id
          <input
            className="mt-1 w-full border rounded px-2 py-1"
            value={projectId}
            onChange={(event) => setProjectId(event.target.value)}
          />
        </label>
        <label className="text-sm">
          Target
          <input
            className="mt-1 w-full border rounded px-2 py-1"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
          />
        </label>
        <label className="text-sm">
          Mode
          <select
            className="mt-1 w-full border rounded px-2 py-1"
            value={mode}
            onChange={(event) => setMode(event.target.value)}
          >
            <option value="lab">LAB</option>
            <option value="live_hackerone">LIVE HackerOne</option>
          </select>
        </label>
        <label className="text-sm">
          Strategy
          <select
            className="mt-1 w-full border rounded px-2 py-1"
            value={strategy}
            onChange={(event) => setStrategy(event.target.value)}
          >
            <option value="passive_recon">Passive recon</option>
            <option value="authorization">Authorization</option>
            <option value="api_behavior">API behavior</option>
            <option value="reproduction">Reproduction</option>
          </select>
        </label>
        <div className="flex items-end gap-2">
          <button
            className="bg-indigo-600 text-white px-3 py-2 rounded text-sm disabled:opacity-50"
            onClick={() => void createAndStart()}
            disabled={busy}
          >
            Create project + session
          </button>
        </div>
      </section>

      {error ? <p className="text-sm text-red-600">{error}</p> : null}

      {dashboard ? (
        <section className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="px-2 py-1 rounded bg-slate-900 text-white">{sessionKind}</span>
            <span className="px-2 py-1 rounded bg-amber-100 text-amber-900">{executionMode}</span>
            <span className="px-2 py-1 rounded bg-slate-100">{String(dashboard.research_state)}</span>
          </div>
          <dl className="grid md:grid-cols-3 gap-3 text-sm">
            <div>
              <dt className="text-slate-500">Target</dt>
              <dd>{String(dashboard.target)}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Strategy</dt>
              <dd>{String(dashboard.strategy)}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Evidence completeness</dt>
              <dd>{String(dashboard.evidence_completeness)}</dd>
            </div>
          </dl>
          <div className="flex flex-wrap gap-2">
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void step()} disabled={busy}>
              Step
            </button>
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void control("pause")} disabled={busy}>
              Pause
            </button>
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void control("resume")} disabled={busy}>
              Resume
            </button>
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void control("stop")} disabled={busy}>
              Stop
            </button>
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void refresh()} disabled={busy}>
              Refresh
            </button>
          </div>
        </section>
      ) : null}

      <section className="grid md:grid-cols-2 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h2 className="font-medium mb-2">Timeline</h2>
          <ul className="text-xs space-y-2 max-h-80 overflow-auto">
            {timeline.map((item, index) => (
              <li key={index} className="border-b border-slate-100 pb-2">
                <div>{String(item.event_type)} · {String(item.tool || "")}</div>
                <div className="text-slate-500">{String(item.decision || item.result || "")}</div>
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h2 className="font-medium mb-2">Findings</h2>
          <ul className="text-xs space-y-2">
            {findings.map((item) => (
              <li key={String(item.id)} className="border-b border-slate-100 pb-2">
                <div className="font-medium">{String(item.title)}</div>
                <div>
                  {String(item.verification_state)} · {String(item.vulnerability_class)}
                </div>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
