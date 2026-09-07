import Link from "next/link";

const FEATURES = [
  {
    title: "Autonomous Discovery",
    desc: "Continuously discovers public GitHub repositories via the GitHub Search API. Filters by stars, language, license, recency, and configurable safety policy.",
    href: "/discovery",
    badge: "v1.1",
  },
  {
    title: "Safety Screening",
    desc: "Every repository is screened before cloning. Blocked topics, excluded owners, size limits, and license requirements are checked deterministically.",
    href: "/repositories",
    badge: "v1.1",
  },
  {
    title: "Local AI First",
    desc: "Supports Ollama and any OpenAI-compatible local endpoint. Repository data never leaves your machine unless you explicitly configure a cloud provider.",
    href: "/ai",
    badge: "v1.1",
  },
  {
    title: "Evidence-First Debugging",
    desc: "Every AI hypothesis is a candidate until executable evidence verifies it. No unverified patch is ever pushed to GitHub.",
    href: "/projects",
    badge: null,
  },
  {
    title: "Automated Repair",
    desc: "Phase 7 generates patch candidates. Phase 8 runs before/after test suites and static analysis. Only verified patches can be delivered.",
    href: "/projects",
    badge: null,
  },
  {
    title: "GitHub Integration",
    desc: "Delivers verified patches as pull requests. Unverified, rejected, or inconclusive candidates are blocked from delivery.",
    href: "/projects",
    badge: null,
  },
];

export default function HomePage() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-5xl font-bold text-slate-900 mb-4">
        Bug<span className="text-indigo-600">Forge</span>
        <span className="ml-3 text-lg font-normal text-slate-400">v1.1.0</span>
      </h1>
      <p className="text-xl text-slate-500 mb-10 max-w-2xl mx-auto">
        Autonomous GitHub repository discovery, safety screening, local AI analysis,
        and evidence-based bug discovery with Docker sandboxing.
      </p>
      <div className="flex flex-wrap gap-4 justify-center">
        <Link
          href="/discovery"
          className="px-6 py-3 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition-colors"
        >
          Run Discovery
        </Link>
        <Link
          href="/repositories"
          className="px-6 py-3 border border-slate-300 text-slate-700 rounded-lg font-medium hover:bg-slate-100 transition-colors"
        >
          View Repositories
        </Link>
        <Link
          href="/ai"
          className="px-6 py-3 border border-slate-300 text-slate-700 rounded-lg font-medium hover:bg-slate-100 transition-colors"
        >
          AI Status
        </Link>
        <Link
          href="/projects"
          className="px-6 py-3 border border-slate-300 text-slate-700 rounded-lg font-medium hover:bg-slate-100 transition-colors"
        >
          Projects
        </Link>
      </div>

      <div className="mt-20 grid grid-cols-1 sm:grid-cols-3 gap-6 max-w-5xl mx-auto text-left">
        {FEATURES.map((card) => (
          <Link
            key={card.title}
            href={card.href}
            className="block bg-white border border-slate-200 rounded-xl p-6 shadow-sm hover:shadow-md transition-shadow"
          >
            <div className="flex items-start justify-between mb-2">
              <h3 className="font-semibold text-slate-900">{card.title}</h3>
              {card.badge && (
                <span className="ml-2 shrink-0 px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-600 text-xs font-semibold">
                  {card.badge}
                </span>
              )}
            </div>
            <p className="text-sm text-slate-500">{card.desc}</p>
          </Link>
        ))}
      </div>
    </div>
  );
}

