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
  const [evidence, setEvidence] = useState<Array<Record<string, unknown>>>([]);
  const [identities, setIdentities] = useState<Record<string, unknown> | null>(null);
  const [graph, setGraph] = useState<Record<string, unknown> | null>(null);
  const [review, setReview] = useState<Record<string, unknown> | null>(null);
  const [timelineTool, setTimelineTool] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [operatorToken, setOperatorToken] = useState("");
  const [disableTool, setDisableTool] = useState("fuzz");

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
      await loadAll(id);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to start research");
    } finally {
      setBusy(false);
    }
  }

  async function loadAll(id: string) {
    const params: Record<string, string> = {};
    if (timelineTool) params.tool = timelineTool;
    const [dash, events, found, evid, ident, graphView] = await Promise.all([
      api.research.dashboard(id),
      api.research.timeline(id, params),
      api.research.findings(id),
      api.research.evidence(id),
      api.research.identities(id),
      api.research.graph(id),
    ]);
    setDashboard(dash);
    setTimeline(Array.isArray(events.items) ? (events.items as Array<Record<string, unknown>>) : []);
    setFindings(Array.isArray(found.items) ? (found.items as Array<Record<string, unknown>>) : []);
    setEvidence(Array.isArray(evid.items) ? (evid.items as Array<Record<string, unknown>>) : []);
    setIdentities(ident);
    setGraph(graphView);
  }

  async function refresh() {
    if (!sessionId) return;
    setBusy(true);
    try {
      await loadAll(sessionId);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Refresh failed");
    } finally {
      setBusy(false);
    }
  }

  async function control(action: string, extra: Record<string, unknown> = {}) {
    if (!sessionId) return;
    setBusy(true);
    try {
      await api.research.override(sessionId, { action, ...extra });
      await loadAll(sessionId);
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
      await loadAll(sessionId);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Step failed");
      setBusy(false);
    }
  }

  async function reviewNext() {
    if (!sessionId) return;
    setBusy(true);
    try {
      const body = await api.research.reviewNext(sessionId, {
        tool: "http_request",
        arguments: { method: "GET", url: target },
        reason: "observe target",
      });
      setReview(body);
      await loadAll(sessionId);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Review failed");
    } finally {
      setBusy(false);
    }
  }

  async function exportPackage() {
    if (!sessionId) return;
    setBusy(true);
    try {
      await api.research.exportPackage(sessionId);
      await loadAll(sessionId);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Export failed");
    } finally {
      setBusy(false);
    }
  }

  const sessionKind = String(dashboard?.session_kind || mode.toUpperCase());
  const executionMode = String(dashboard?.execution_mode || "DRY-RUN");
  const budget = (dashboard?.remaining_budget || {}) as Record<string, unknown>;
  const identityA = (identities?.a || null) as Record<string, unknown> | null;
  const identityB = (identities?.b || null) as Record<string, unknown> | null;

  return (
    <main className="max-w-6xl mx-auto p-6 space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-900">Security Research Workbench</h1>
        <p className="text-sm text-slate-600 mt-1">
          Guided research. ScopeGuard, SafetyController, and human review remain authoritative.
          The AI cannot verify findings, grant approvals, or submit reports. Credentials are never
          displayed.
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
            <span className="px-2 py-1 rounded bg-slate-100">
              {String(dashboard.termination_reason || "running")}
            </span>
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
            <div>
              <dt className="text-slate-500">Current hypothesis</dt>
              <dd>
                {dashboard.current_hypothesis
                  ? JSON.stringify(dashboard.current_hypothesis).slice(0, 180)
                  : "none"}
              </dd>
            </div>
            <div>
              <dt className="text-slate-500">Remaining requests</dt>
              <dd>{String(budget.requests ?? "n/a")}</dd>
            </div>
            <div>
              <dt className="text-slate-500">Approval status</dt>
              <dd>{JSON.stringify(dashboard.approval_status || {}).slice(0, 180)}</dd>
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
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void reviewNext()} disabled={busy}>
              Review next HTTP
            </button>
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void exportPackage()} disabled={busy}>
              Export
            </button>
            <button className="border px-3 py-1 rounded text-sm" onClick={() => void refresh()} disabled={busy}>
              Refresh
            </button>
          </div>
          <div className="flex flex-wrap gap-2 items-end">
            <label className="text-sm">
              Tool
              <input
                className="mt-1 border rounded px-2 py-1"
                value={disableTool}
                onChange={(event) => setDisableTool(event.target.value)}
              />
            </label>
            <button
              className="border px-3 py-1 rounded text-sm"
              onClick={() => void control("disable_tool", { tool: disableTool })}
              disabled={busy}
            >
              Disable tool
            </button>
            <button
              className="border px-3 py-1 rounded text-sm"
              onClick={() => void control("enable_tool", { tool: disableTool })}
              disabled={busy}
            >
              Re-enable tool
            </button>
            <button
              className="border px-3 py-1 rounded text-sm"
              onClick={() => void control("change_strategy", { strategy })}
              disabled={busy}
            >
              Change strategy
            </button>
          </div>
        </section>
      ) : null}

      {review ? (
        <section className="bg-white border border-slate-200 rounded-lg p-4 text-sm space-y-1">
          <h2 className="font-medium">Next action review</h2>
          <p>What: {String(review.what)}</p>
          <p>Why: {String(review.why)}</p>
          <p>Tool: {String(review.tool)}</p>
          <p>Estimated requests: {String(review.estimated_requests)} (estimate)</p>
          <p>Risk: {String(review.risk_level)}</p>
          <p>Approval required: {String(review.approval_required)}</p>
          <p>Scope: {String(review.current_scope_decision)}</p>
        </section>
      ) : null}

      <section className="grid md:grid-cols-2 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h2 className="font-medium mb-2">Timeline</h2>
          <label className="text-xs block mb-2">
            Filter by tool
            <input
              className="mt-1 w-full border rounded px-2 py-1"
              value={timelineTool}
              onChange={(event) => setTimelineTool(event.target.value)}
              onBlur={() => void refresh()}
            />
          </label>
          <ul className="text-xs space-y-2 max-h-80 overflow-auto">
            {timeline.map((item, index) => (
              <li key={index} className="border-b border-slate-100 pb-2">
                <div>
                  {String(item.timestamp || item.time || "")} · {String(item.event_type)} ·{" "}
                  {String(item.tool || "")}
                </div>
                <div className="text-slate-500">
                  {String(item.authorization || "")} {String(item.decision || item.result || "")}
                </div>
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
                  {String(item.verification_state)} · {String(item.vulnerability_class)} ·{" "}
                  {String(item.severity)}
                </div>
                <button
                  className="mt-1 border px-2 py-0.5 rounded"
                  onClick={() => void control("reject_finding", { finding_id: item.id })}
                >
                  Reject
                </button>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="grid md:grid-cols-2 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h2 className="font-medium mb-2">Evidence explorer</h2>
          <ul className="text-xs space-y-2 max-h-80 overflow-auto">
            {evidence.map((item) => (
              <li key={String(item.id)} className="border-b border-slate-100 pb-2">
                <div>
                  {String(item.kind)} · {String(item.provenance)} · {String(item.tool || "")}
                </div>
                <div className="text-slate-500">{String(item.summary)}</div>
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h2 className="font-medium mb-2">Identities</h2>
          <p className="text-xs text-slate-500 mb-2">
            Isolated: {String(identities?.isolated ?? false)}. Raw credentials are never shown.
          </p>
          <pre className="text-xs whitespace-pre-wrap">
            {JSON.stringify(
              {
                a: identityA
                  ? {
                      id: identityA.id,
                      authentication_state: identityA.authentication_state,
                      credential_availability: identityA.credential_availability,
                      browser_context_id: identityA.browser_context_id,
                      http_session_id: identityA.http_session_id,
                    }
                  : null,
                b: identityB
                  ? {
                      id: identityB.id,
                      authentication_state: identityB.authentication_state,
                      credential_availability: identityB.credential_availability,
                      browser_context_id: identityB.browser_context_id,
                      http_session_id: identityB.http_session_id,
                    }
                  : null,
              },
              null,
              2,
            )}
          </pre>
          {graph ? (
            <p className="text-xs mt-3 text-slate-500">
              Graph nodes: {Array.isArray(graph.nodes) ? graph.nodes.length : 0} · edges:{" "}
              {Array.isArray(graph.edges) ? graph.edges.length : 0}
            </p>
          ) : null}
        </div>
      </section>
    </main>
  );
}
