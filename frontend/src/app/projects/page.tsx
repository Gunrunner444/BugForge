"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { Project } from "@/lib/types";
import ProjectCard from "@/components/ProjectCard";
import LoadingSpinner from "@/components/ui/LoadingSpinner";

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.projects
      .list()
      .then((data) => {
        setProjects(data.items);
        setTotal(data.total);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Projects</h1>
          {!loading && (
            <p className="text-sm text-slate-500 mt-1">
              {total} project{total !== 1 ? "s" : ""}
            </p>
          )}
        </div>
        <Link
          href="/projects/new"
          className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors"
        >
          + New Project
        </Link>
      </div>

      {loading && (
        <div className="flex justify-center py-20">
          <LoadingSpinner />
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-800 rounded-lg p-4 text-sm">
          Failed to load projects: {error}
        </div>
      )}

      {!loading && !error && projects.length === 0 && (
        <div className="text-center py-20 text-slate-400">
          <p className="text-lg mb-4">No projects yet.</p>
          <Link href="/projects/new" className="text-indigo-600 hover:underline">
            Add your first project →
          </Link>
        </div>
      )}

      {!loading && !error && projects.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {projects.map((project) => (
            <ProjectCard key={project.id} project={project} />
          ))}
        </div>
      )}
    </div>
  );
}
