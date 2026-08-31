import Link from "next/link";
import type { Project } from "@/lib/types";
import { formatDate, statusColor } from "@/lib/utils";

interface Props {
  project: Project;
}

export default function ProjectCard({ project }: Props) {
  return (
    <Link
      href={`/projects/${project.id}`}
      className="block bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:shadow-md hover:border-indigo-300 transition-all"
    >
      <div className="flex items-start justify-between gap-2">
        <h3 className="font-semibold text-slate-900 text-base leading-tight">{project.name}</h3>
        {project.latest_analysis_status && (
          <span
            className={`text-xs font-medium px-2 py-0.5 rounded-full whitespace-nowrap ${statusColor(
              project.latest_analysis_status
            )}`}
          >
            {project.latest_analysis_status}
          </span>
        )}
      </div>

      {project.description && (
        <p className="text-sm text-slate-500 mt-1 line-clamp-2">{project.description}</p>
      )}

      <p className="text-xs text-slate-400 font-mono mt-3 truncate" title={project.repository_path}>
        {project.repository_path}
      </p>

      <p className="text-xs text-slate-400 mt-2">Created {formatDate(project.created_at)}</p>
    </Link>
  );
}
