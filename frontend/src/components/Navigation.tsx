import Link from "next/link";

export default function Navigation() {
  return (
    <nav className="bg-white border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center h-14 gap-8">
          <Link href="/" className="font-bold text-xl text-slate-900">
            Bug<span className="text-indigo-600">Forge</span>
          </Link>
          <div className="flex gap-6 text-sm">
            <Link
              href="/projects"
              className="text-slate-600 hover:text-slate-900 transition-colors"
            >
              Projects
            </Link>
          </div>
        </div>
      </div>
    </nav>
  );
}
