import Link from "next/link";

const NAV_LINKS = [
  { href: "/projects", label: "Projects" },
  { href: "/discovery", label: "Discovery" },
  { href: "/repositories", label: "Repositories" },
  { href: "/autonomous", label: "Analysis Runs" },
  { href: "/ai", label: "AI" },
];

export default function Navigation() {
  return (
    <nav className="bg-white border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center h-14 gap-8">
          <Link href="/" className="font-bold text-xl text-slate-900 shrink-0">
            Bug<span className="text-indigo-600">Forge</span>
            <span className="ml-1 text-xs font-normal text-slate-400">v1.1</span>
          </Link>
          <div className="flex gap-6 text-sm overflow-x-auto">
            {NAV_LINKS.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className="text-slate-600 hover:text-slate-900 transition-colors whitespace-nowrap"
              >
                {label}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </nav>
  );
}

