import type { AnalysisStatus } from "./types";

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function statusColor(status: AnalysisStatus): string {
  switch (status) {
    case "completed":
      return "bg-emerald-100 text-emerald-800";
    case "running":
      return "bg-blue-100 text-blue-800";
    case "pending":
      return "bg-yellow-100 text-yellow-800";
    case "failed":
      return "bg-red-100 text-red-800";
    default:
      return "bg-gray-100 text-gray-800";
  }
}

export function languageColor(lang: string): string {
  const map: Record<string, string> = {
    python: "bg-blue-100 text-blue-800",
    typescript: "bg-sky-100 text-sky-800",
    javascript: "bg-yellow-100 text-yellow-800",
    go: "bg-teal-100 text-teal-800",
    rust: "bg-orange-100 text-orange-800",
    java: "bg-amber-100 text-amber-800",
  };
  return map[lang.toLowerCase()] ?? "bg-gray-100 text-gray-700";
}

export function pluralize(n: number, singular: string, plural?: string): string {
  return `${n} ${n === 1 ? singular : (plural ?? singular + "s")}`;
}
