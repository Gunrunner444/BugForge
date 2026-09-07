"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { AIStatus } from "@/lib/types";

function StatusIndicator({ ok, label }: { ok: boolean | null; label: string }) {
  const colour = ok === true ? "text-green-600" : ok === false ? "text-red-600" : "text-gray-400";
  const icon = ok === true ? "✓" : ok === false ? "✗" : "?";
  return (
    <span className={`${colour} text-sm font-medium`}>
      {icon} {label}
    </span>
  );
}

export default function AIPage() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testPrompt, setTestPrompt] = useState("Reply with only the word: ok");
  const [testResult, setTestResult] = useState<{
    response: string; duration_seconds: number; error: string | null;
  } | null>(null);
  const [testing, setTesting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  async function loadStatus() {
    setRefreshing(true);
    try {
      const s = await api.ai.status();
      setStatus(s);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach backend");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadStatus();
  }, []);

  async function runTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await api.ai.test(testPrompt);
      setTestResult({ response: r.response, duration_seconds: r.duration_seconds, error: r.error });
    } catch (e) {
      setTestResult({ response: "", duration_seconds: 0, error: e instanceof Error ? e.message : "unknown error" });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="max-w-3xl mx-auto py-8 px-4">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">AI Provider</h1>
        <button
          onClick={loadStatus}
          disabled={refreshing}
          className="px-4 py-2 rounded-lg border border-gray-300 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          {refreshing ? "Refreshing…" : "Refresh Status"}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {loading ? (
        <div className="p-8 text-center text-sm text-gray-400">Loading…</div>
      ) : status ? (
        <>
          {/* Status card */}
          <div className="rounded-lg border border-gray-200 bg-white p-6 mb-6">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Provider</p>
                <p className="mt-1 text-lg font-semibold text-gray-900">{status.provider}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Model</p>
                <p className="mt-1 text-lg font-semibold text-gray-900">{status.model}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Type</p>
                <p className={`mt-1 font-semibold ${status.is_local ? "text-green-700" : "text-blue-700"}`}>
                  {status.is_local ? "Local (no cloud cost)" : "Cloud"}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Status</p>
                <div className="mt-1 flex flex-col gap-1">
                  <StatusIndicator ok={status.configured} label="Configured" />
                  <StatusIndicator ok={status.reachable} label="Reachable" />
                  <StatusIndicator ok={status.model_available} label="Model available" />
                </div>
              </div>
            </div>

            {status.error && (
              <div className="mt-4 rounded bg-red-50 border border-red-200 p-3 text-xs text-red-700">
                {status.error}
              </div>
            )}

            {status.capabilities && (
              <div className="mt-4">
                <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Capabilities</p>
                <div className="flex flex-wrap gap-2">
                  {status.capabilities.map((cap) => (
                    <span key={cap} className="px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 text-xs font-medium">
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Ollama setup guide */}
          {status.provider === "ollama" && !status.reachable && (
            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4 mb-6 text-sm text-yellow-800">
              <p className="font-semibold mb-2">Ollama not reachable</p>
              <ol className="list-decimal list-inside space-y-1 text-xs">
                <li>Install Ollama from <a href="https://ollama.com" target="_blank" rel="noopener noreferrer" className="underline">ollama.com</a></li>
                <li>Start Ollama: <code className="bg-yellow-100 px-1 rounded">ollama serve</code></li>
                <li>Pull a model: <code className="bg-yellow-100 px-1 rounded">ollama pull {status.model}</code></li>
                <li>Set <code className="bg-yellow-100 px-1 rounded">AI_BASE_URL=http://localhost:11434/v1</code> in your <code>.env</code></li>
                <li>Restart BugForge backend</li>
              </ol>
            </div>
          )}

          {/* Test prompt */}
          <div className="rounded-lg border border-gray-200 bg-white p-6">
            <h2 className="text-sm font-semibold text-gray-700 mb-3">Test Connection</h2>
            <div className="flex gap-2 mb-3">
              <input
                type="text"
                value={testPrompt}
                onChange={(e) => setTestPrompt(e.target.value)}
                maxLength={500}
                className="flex-1 rounded-lg border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="Test prompt…"
              />
              <button
                onClick={runTest}
                disabled={testing || !testPrompt.trim()}
                className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-medium hover:bg-indigo-700 disabled:opacity-50"
              >
                {testing ? "Sending…" : "Send"}
              </button>
            </div>

            {testResult && (
              <div className={`rounded p-3 text-sm ${testResult.error ? "bg-red-50 border border-red-200" : "bg-green-50 border border-green-200"}`}>
                {testResult.error ? (
                  <p className="text-red-700">{testResult.error}</p>
                ) : (
                  <>
                    <p className="text-green-800 font-medium">{testResult.response}</p>
                    <p className="text-xs text-green-600 mt-1">{testResult.duration_seconds.toFixed(2)}s</p>
                  </>
                )}
              </div>
            )}
          </div>

          {/* Configuration reference */}
          <div className="mt-6 rounded-lg border border-gray-200 bg-gray-50 p-4">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Environment Variables</p>
            <pre className="text-xs text-gray-600 overflow-x-auto whitespace-pre-wrap">
{`AI_PROVIDER=ollama            # mock | openai | anthropic | ollama | openai_compatible
AI_MODEL=qwen2.5-coder:7b     # any model you have available
AI_BASE_URL=http://localhost:11434/v1
AI_API_KEY=                   # empty for Ollama; required for OpenAI / Anthropic`}
            </pre>
          </div>
        </>
      ) : null}
    </div>
  );
}
