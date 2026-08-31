import Link from "next/link";

export default function HomePage() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-5xl font-bold text-slate-900 mb-4">
        Bug<span className="text-indigo-600">Forge</span>
      </h1>
      <p className="text-xl text-slate-500 mb-10 max-w-2xl mx-auto">
        AI-powered software debugging, testing, and automated code repair.
        Analyze repositories, trace root causes, and verify fixes with evidence.
      </p>
      <div className="flex gap-4 justify-center">
        <Link
          href="/projects"
          className="px-6 py-3 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition-colors"
        >
          View Projects
        </Link>
        <Link
          href="/projects/new"
          className="px-6 py-3 border border-slate-300 text-slate-700 rounded-lg font-medium hover:bg-slate-100 transition-colors"
        >
          New Project
        </Link>
      </div>

      <div className="mt-20 grid grid-cols-1 sm:grid-cols-3 gap-8 max-w-4xl mx-auto text-left">
        {[
          {
            title: "Repository Analysis",
            desc: "Detect languages, frameworks, and project structure. Parse Python source files and extract functions, classes, and imports.",
          },
          {
            title: "Structured Results",
            desc: "Every finding is backed by evidence — file paths, line numbers, and code entities. No guessing.",
          },
          {
            title: "Extensible Foundation",
            desc: "Phase 1 delivers the analyzer core. Phases 2–8 add test execution, AI debugging, automated repair, and GitHub integration.",
          },
        ].map((card) => (
          <div key={card.title} className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
            <h3 className="font-semibold text-slate-900 mb-2">{card.title}</h3>
            <p className="text-sm text-slate-500">{card.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
