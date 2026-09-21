"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { AuthorizationDecision, SecurityTestingSessionResponse } from "@/lib/types";

const STATUS_KEYS = ["potential", "corroborated", "reproduced", "verified", "human_accepted", "rejected"] as const;

export default function SecurityTestingPage() {
  const [projectId, setProjectId] = useState("lab-project");
  const [session, setSession] = useState<SecurityTestingSessionResponse | null>(null);
  const [decision, setDecision] = useState<AuthorizationDecision | null>(null);
  const [target, setTarget] = useState("http://127.0.0.1:5000/health");
  const [tool, setTool] = useState("browser");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [handle, setHandle] = useState("");
  const [h1, setH1] = useState<Record<string, unknown> | null>(null);
  const [program, setProgram] = useState<Record<string, unknown> | null>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [dryRun, setDryRun] = useState<Record<string, unknown> | null>(null);
  const [operatorToken, setOperatorToken] = useState("");
  const [findingId, setFindingId] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [weakness, setWeakness] = useState("1338");

  async function createLab() {
    setBusy(true);
    setError(null);
    try {
      const created = await api.securityTesting.createSession({
        project_id: projectId,
        mode: "lab",
        program_name: "local-lab",
        includes: [
          { identifier: "127.0.0.1", allow_active_testing: true },
          { identifier: "localhost", allow_active_testing: true },
        ],
        allow_active_testing: false,
        dry_run: true,
        allowed_methods: ["GET", "HEAD", "OPTIONS"],
      });
      setSession(created);
      setDecision(null);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Failed to create session");
    } finally {
      setBusy(false);
    }
  }

  async function authorize() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.securityTesting.authorize(projectId, {
        target,
        method: "GET",
        tool,
        active: true,
      });
      setDecision(result);
      const refreshed = await api.securityTesting.getSession(projectId);
      setSession(refreshed);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Authorization failed");
    } finally {
      setBusy(false);
    }
  }

  async function loadHackerOne() {
    try {
      setH1(await api.hackerone.status());
    } catch {
      setH1(null);
    }
  }

  async function syncProgram() {
    setBusy(true);
    setError(null);
    try {
      if (operatorToken) sessionStorage.setItem("bugforge_operator_token", operatorToken);
      const synced = await api.hackerone.sync(handle);
      setProgram(synced);
      await loadHackerOne();
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Program sync failed");
    } finally {
      setBusy(false);
    }
  }

  async function generateReport() {
    setBusy(true);
    setError(null);
    try {
      if (operatorToken) sessionStorage.setItem("bugforge_operator_token", operatorToken);
      const created = await api.hackerone.createDraft({
        program_handle: handle,
        project_id: projectId,
        finding_id: findingId,
        severity,
        weakness_id: weakness ? Number(weakness) : undefined,
      });
      setDraft(created);
      setDryRun(null);
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Draft failed");
    } finally {
      setBusy(false);
    }
  }

  async function reviewReport() {
    if (!draft?.id) return;
    setBusy(true);
    try {
      setDraft(await api.hackerone.review(String(draft.id), handle));
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Review failed");
    } finally {
      setBusy(false);
    }
  }

  async function runDryRun() {
    if (!draft?.id) return;
    setBusy(true);
    try {
      setDryRun(await api.hackerone.dryRun(String(draft.id), handle));
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Dry-run failed");
    } finally {
      setBusy(false);
    }
  }

  async function approveSubmission() {
    if (!draft?.id) return;
    setBusy(true);
    try {
      setDraft(await api.hackerone.approve(String(draft.id), handle));
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Approval failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitReport() {
    if (!draft?.id) return;
    setBusy(true);
    try {
      setDraft(await api.hackerone.submit(String(draft.id), handle));
    } catch (err) {
      setError(err instanceof ApiError ? (err.detail ?? err.message) : "Submit failed");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    api.securityTesting
      .getSession(projectId)
      .then(setSession)
      .catch(() => setSession(null));
    void loadHackerOne();
  }, [projectId]);

  const snap = session?.session;
  const counts = snap?.finding_counts ?? {};
  const approved = draft?.human_review_state === "human_approved";
  const validationOk = Boolean((dryRun?.validation as { ok?: boolean } | undefined)?.ok);
  const submitEnabled = Boolean(approved && validationOk && !busy);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Security Testing</h1>
        <p className="text-sm text-slate-600 mt-1">
          Authorized, scope-aware testing. There is no unrestricted scan action. The operator remains
          responsible for enabling active testing and for any later report.
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded-lg p-3">{error}</div>
      )}

      <section className="grid md:grid-cols-3 gap-4">
        <Card title="Project" value={snap?.project_id ?? projectId} />
        <Card title="Program / Lab" value={snap ? `${snap.program ?? "—"} (${snap.mode})` : "No session"} />
        <Card title="Scope status" value={snap?.lab_mode ? "Lab isolated" : "Live (closed default)"} />
        <Card title="Active testing" value={snap?.active_testing ? "enabled" : "disabled"} />
        <Card title="Rate limit" value={snap ? `${snap.rate_limit_rps} rps / ${snap.request_limit} max` : "—"} />
        <Card title="Dry-run" value={snap?.dry_run ? "yes" : "no"} />
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
        <h2 className="font-semibold text-slate-800">HackerOne Program</h2>
        <p className="text-xs text-slate-500">
          Tokens stay in environment variables. Approval uses a local operator token, not a free-form
          operator name. Dry-run never creates a HackerOne report. Submit stays disabled until
          deterministic checks pass and HUMAN_APPROVED exists for the current payload hash.
        </p>
        <div className="grid md:grid-cols-3 gap-3">
          <Card title="Connection" value={h1?.configured ? "credentials configured" : "not configured"} />
          <Card title="Last scope sync" value={String(program?.fetched_at ?? "never")} />
          <Card title="Scope count" value={String(program?.scope_count ?? 0)} />
          <Card title="Scope snapshot" value={String(program?.scope_version ?? "none")} />
          <Card title="Scope exclusions" value={String(program?.exclusion_count ?? 0)} />
          <Card title="Weaknesses" value={String(program?.weakness_count ?? 0)} />
          <Card title="Sync complete" value={program?.scope_sync_complete ? "yes" : "no"} />
          <Card title="Active testing" value={program?.active_testing_approved ? "approved" : "not approved"} />
          <Card title="Sync status" value={String(program?.sync_status ?? "unknown")} />
        </div>
        <div className="grid md:grid-cols-3 gap-3">
          <label className="text-sm">
            Program handle
            <input className="mt-1 w-full border rounded px-2 py-1" value={handle} onChange={(e) => setHandle(e.target.value)} />
          </label>
          <label className="text-sm">
            Local operator token
            <input
              type="password"
              className="mt-1 w-full border rounded px-2 py-1"
              value={operatorToken}
              onChange={(e) => {
                setOperatorToken(e.target.value);
                sessionStorage.setItem("bugforge_operator_token", e.target.value);
              }}
            />
          </label>
          <div className="flex items-end">
            <button type="button" onClick={syncProgram} disabled={busy || !handle} className="px-3 py-2 text-sm rounded border border-slate-300 hover:bg-slate-50">
              Sync program
            </button>
          </div>
        </div>
        <div className="grid md:grid-cols-2 gap-3">
          <label className="text-sm">
            Persisted finding id
            <input className="mt-1 w-full border rounded px-2 py-1" value={findingId} onChange={(e) => setFindingId(e.target.value)} />
          </label>
          <label className="text-sm">
            Project id
            <input className="mt-1 w-full border rounded px-2 py-1" value={projectId} onChange={(e) => setProjectId(e.target.value)} />
          </label>
          <label className="text-sm">
            Severity
            <select className="mt-1 w-full border rounded px-2 py-1" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="informational">informational</option>
            </select>
          </label>
          <label className="text-sm">
            HackerOne weakness id (numeric)
            <input className="mt-1 w-full border rounded px-2 py-1" value={weakness} onChange={(e) => setWeakness(e.target.value)} />
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={generateReport} disabled={busy || !handle} className="px-3 py-2 text-sm rounded border">
            Generate Report
          </button>
          <button type="button" onClick={reviewReport} disabled={busy || !draft} className="px-3 py-2 text-sm rounded border">
            Review Report
          </button>
          <button type="button" onClick={runDryRun} disabled={busy || !draft} className="px-3 py-2 text-sm rounded border">
            Dry Run
          </button>
          <button type="button" onClick={approveSubmission} disabled={busy || !draft} className="px-3 py-2 text-sm rounded border">
            Approve Submission
          </button>
          <button
            type="button"
            onClick={submitReport}
            disabled={!submitEnabled}
            className="px-3 py-2 text-sm rounded bg-indigo-600 text-white disabled:opacity-40"
          >
            Submit
          </button>
        </div>
        {draft && (
          <div className="text-xs text-slate-600 space-y-1">
            <p>
              Draft {String(draft.id)} — DRAFT / {String(draft.human_review_state)} / {String(draft.submission_state)} / remote {String(draft.remote_state)}
            </p>
            <p>Payload hash: {String(draft.report_content_hash ?? "—")}</p>
            <p>Evidence hash: {String(draft.evidence_hash ?? "—")}</p>
            <p>Scope snapshot: {String(draft.scope_snapshot_hash ?? "—")}</p>
            <p>
              Weakness {String(draft.weakness_id ?? "—")} · Severity {String(draft.severity ?? "—")} · Target {String(draft.target ?? "—")} · Program {String(draft.program_handle ?? handle)}
            </p>
            <p>Approved by {String(draft.approved_by ?? "—")} at {String(draft.approval_timestamp ?? "—")}</p>
            <pre className="bg-slate-50 border rounded p-3 overflow-auto max-h-40">{String(draft.vulnerability_information ?? "")}</pre>
          </div>
        )}
        {dryRun && (
          <pre className="text-xs bg-slate-50 border rounded p-3 overflow-auto max-h-56">{JSON.stringify(dryRun, null, 2)}</pre>
        )}
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
        <h2 className="font-semibold text-slate-800">Tools</h2>
        <p className="text-xs text-slate-500">Browser · Proxy · ZAP · Nuclei · API · Fuzzing</p>
        <div className="flex flex-wrap gap-2 text-xs">
          {(session?.tools ?? ["playwright", "har", "burp", "zap", "nuclei"]).map((name) => (
            <span key={name} className="px-2 py-1 rounded border border-slate-200 bg-slate-50">
              {name}
            </span>
          ))}
        </div>
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-4">
        <h2 className="font-semibold text-slate-800 mb-3">Findings</h2>
        <div className="flex flex-wrap gap-2 text-xs">
          {STATUS_KEYS.map((key) => (
            <span key={key} className="px-2 py-1 rounded border border-slate-200">
              {key.replace("_", " ")}: {counts[key] ?? 0}
            </span>
          ))}
        </div>
        <p className="text-xs text-slate-500 mt-2">Human review is required. AI-only claims never count as verified.</p>
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
        <h2 className="font-semibold text-slate-800">Authorize an operation</h2>
        <div className="grid md:grid-cols-2 gap-3">
          <label className="text-sm">
            Project
            <input
              className="mt-1 w-full border rounded px-2 py-1"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            />
          </label>
          <label className="text-sm">
            Tool
            <select className="mt-1 w-full border rounded px-2 py-1" value={tool} onChange={(e) => setTool(e.target.value)}>
              <option value="browser">browser</option>
              <option value="zap">zap</option>
              <option value="nuclei">nuclei</option>
              <option value="api_test">api</option>
              <option value="fuzzer">fuzzing</option>
              <option value="proxy">proxy</option>
            </select>
          </label>
          <label className="text-sm md:col-span-2">
            Target
            <input className="mt-1 w-full border rounded px-2 py-1" value={target} onChange={(e) => setTarget(e.target.value)} />
          </label>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={createLab}
            disabled={busy}
            className="px-3 py-2 text-sm rounded border border-slate-300 hover:bg-slate-50"
          >
            Open lab session
          </button>
          <button
            type="button"
            onClick={authorize}
            disabled={busy || !session}
            className="px-3 py-2 text-sm rounded bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            Check authorization
          </button>
        </div>
        {decision && (
          <dl className="grid md:grid-cols-2 gap-2 text-sm bg-slate-50 border border-slate-200 rounded p-3">
            <Row label="Target" value={decision.target} />
            <Row label="Tool" value={decision.tool} />
            <Row label="Scope decision" value={decision.allowed ? "allowed" : "denied"} />
            <Row label="Reason" value={decision.reason} />
            <Row label="Request limit" value={String(decision.request_limit ?? "—")} />
            <Row label="Human approval" value={decision.approval_state} />
          </dl>
        )}
      </section>
    </div>
  );
}

function Card({ title, value }: { title: string; value: string }) {
  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{title}</p>
      <p className="text-sm font-medium text-slate-900 mt-1">{value}</p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="font-medium text-slate-800">{value}</dd>
    </div>
  );
}
