// All shared TypeScript types mirroring the backend API schemas

export interface Project {
  id: string;
  name: string;
  description: string | null;
  repository_path: string;
  created_at: string;
  updated_at: string;
  latest_analysis_id: string | null;
  latest_analysis_status: AnalysisStatus | null;
}

export type AnalysisStatus = "pending" | "running" | "completed" | "failed";

export interface LanguageStats {
  language: string;
  file_count: number;
  percentage: number;
}

export interface FrameworkDetection {
  name: string;
  language: string;
  confidence: number;
  evidence: string[];
}

export interface AnalysisSummary {
  total_files: number;
  source_files: number;
  test_files: number;
  ignored_files: number;
  total_entities: number;
  total_imports: number;
  total_findings: number;
  languages: LanguageStats[];
  frameworks: FrameworkDetection[];
  analysis_duration_seconds: number | null;
}

export interface Analysis {
  id: string;
  project_id: string;
  status: AnalysisStatus;
  repository_path: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  summary: AnalysisSummary | null;
  created_at: string;
}

export interface RepositoryFile {
  id: string;
  relative_path: string;
  file_type: "source" | "test" | "config" | "other";
  language: string | null;
  size_bytes: number;
  line_count: number;
  has_errors: boolean;
}

export interface CodeEntity {
  id: string;
  file_id: string;
  entity_type: string;
  name: string;
  qualified_name: string;
  start_line: number;
  end_line: number;
  docstring: string | null;
  is_async: boolean;
  decorators: string[] | null;
  parameters: Array<{
    name: string;
    annotation: string | null;
    default: string | null;
    kind: string;
  }> | null;
  return_annotation: string | null;
  parent_name: string | null;
}

export interface ImportRecord {
  id: string;
  file_id: string;
  module_name: string;
  imported_name: string | null;
  alias: string | null;
  import_type: "stdlib" | "third_party" | "relative" | "local";
  line_number: number;
  is_from_import: boolean;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}

export interface ProjectListResponse {
  items: Project[];
  total: number;
}

// ── Test Runs ──────────────────────────────────────────────────────────────

export type TestRunStatus = "pending" | "running" | "completed" | "failed" | "timeout";

export interface TestRun {
  id: string;
  project_id: string;
  status: TestRunStatus;
  framework: string;
  repository_path: string;
  command: string | null;
  exit_code: number | null;
  duration_seconds: number | null;
  error_message: string | null;
  total_tests: number;
  passed: number;
  failed: number;
  skipped: number;
  errors: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  stdout?: string | null;
  stderr?: string | null;
}

export interface TestResult {
  id: string;
  test_run_id: string;
  node_id: string;
  test_file: string | null;
  test_name: string;
  status: "passed" | "failed" | "skipped" | "error" | "timeout";
  duration_seconds: number | null;
  traceback: string | null;
  stdout: string | null;
  stderr: string | null;
  skip_reason: string | null;
}

export interface TestRunListResponse {
  items: TestRun[];
  total: number;
  offset: number;
  limit: number;
}

export interface TestResultListResponse {
  items: TestResult[];
  total: number;
  offset: number;
  limit: number;
}

// ── Static Analysis ────────────────────────────────────────────────────────

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  analysis_id: string;
  category: string;
  severity: FindingSeverity;
  confidence: string;
  file_path: string;
  line: number;
  end_line: number;
  column: number | null;
  message: string;
  explanation: string;
  analyzer: string;
  evidence: string;
  suggested_fix: string;
  created_at: string;
}

export interface FindingsListResponse {
  items: Finding[];
  total: number;
  offset: number;
  limit: number;
}

// ── AI Debugging ───────────────────────────────────────────────────────────

export type DebuggingStatus = "pending" | "running" | "completed" | "failed";

export interface DebuggingHypothesis {
  id: string;
  session_id: string;
  root_cause: string;
  confidence: number;
  confidence_label: "confirmed" | "highly_likely" | "likely" | "possible" | "insufficient_evidence";
  affected_files: string[];
  affected_symbols: string[];
  evidence_summary: string[];
  contradictory_evidence: string[];
  reproduction_strategy: string;
  recommended_tests: string[];
  explanation: string;
  ai_provider: string;
  ai_model: string;
  created_at: string;
}

export interface AIModelCall {
  id: string;
  provider: string;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  duration_seconds: number;
  success: boolean;
  error_message: string | null;
  created_at: string;
}

export interface DebuggingSession {
  id: string;
  project_id: string;
  analysis_id: string | null;
  test_run_id: string | null;
  status: DebuggingStatus;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  hypothesis_count: number;
  hypotheses?: DebuggingHypothesis[];
  ai_calls?: AIModelCall[];
}

export interface DebuggingSessionsListResponse {
  items: DebuggingSession[];
  total: number;
  offset: number;
  limit: number;
}

// ── Test Generation ────────────────────────────────────────────────────────

export type TestGenStatus = "pending" | "running" | "completed" | "failed";
export type ValidationStatus = "pending" | "valid" | "invalid";
export type ExecutionStatus = "pending" | "passed" | "failed" | "error" | "timeout" | "not_run";

export interface TestGenerationSession {
  id: string;
  project_id: string;
  analysis_id: string | null;
  test_run_id: string | null;
  debugging_session_id: string | null;
  status: TestGenStatus;
  error_message: string | null;
  candidate_count: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface GeneratedTest {
  id: string;
  session_id: string;
  project_id: string;
  target_file: string;
  target_symbol: string;
  category: string;
  rationale: string;
  generated_code: string;
  confidence: number;
  validation_status: ValidationStatus;
  validation_error: string | null;
  execution_status: ExecutionStatus;
  execution_output: string | null;
  quality_score: number | null;
  quality_notes: string | null;
  hypothesis_id: string | null;
  created_at: string;
}

export interface TestGenSessionsListResponse {
  items: TestGenerationSession[];
  total: number;
  offset: number;
  limit: number;
}

export interface GeneratedTestsListResponse {
  items: GeneratedTest[];
  total: number;
  offset: number;
  limit: number;
}
