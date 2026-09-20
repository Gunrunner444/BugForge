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
  security_findings?: number;
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

// ── Bug Reproduction ───────────────────────────────────────────────────────

export type ReproductionStatus = "pending" | "running" | "completed" | "failed";
export type ReproductionClassification =
  | "not_reproduced"
  | "inconclusive"
  | "intermittent"
  | "reproduced"
  | "consistently_reproduced";

export interface BugReproductionAttempt {
  id: string;
  session_id: string;
  attempt_number: number;
  command: string | null;
  input_description: string | null;
  reproducer_code: string | null;
  exit_code: number | null;
  stdout: string | null;
  stderr: string | null;
  traceback: string | null;
  duration_seconds: number | null;
  timed_out: boolean;
  reproduced: boolean;
  classification: string;
  created_at: string;
}

export interface BugReproductionSession {
  id: string;
  project_id: string;
  debugging_session_id: string | null;
  hypothesis_id: string | null;
  generated_test_id: string | null;
  status: ReproductionStatus;
  attempt_count: number;
  successful_attempts: number;
  total_attempts: number;
  reproducibility_rate: number | null;
  final_classification: ReproductionClassification | null;
  strategy_summary: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  attempts?: BugReproductionAttempt[];
}

export interface ReproductionSessionsListResponse {
  items: BugReproductionSession[];
  total: number;
  offset: number;
  limit: number;
}

// ── Automated Repair ───────────────────────────────────────────────────────

export type RepairStatus = "pending" | "running" | "completed" | "failed";
export type CandidateDisposition = "pending" | "accepted" | "rejected" | "best";
export type CandidateStatus =
  | "pending"
  | "validating"
  | "applying"
  | "verifying"
  | "completed"
  | "rejected";

export interface PatchCandidate {
  id: string;
  session_id: string;
  rank: number;
  patch_provider: string | null;
  patch_model: string | null;
  patch_plan: string | null;
  patch_diff: string | null;
  changed_files: string[];
  status: CandidateStatus;
  validation_status: string | null;
  validation_error: string | null;
  pre_patch_reproduced: boolean | null;
  post_patch_reproduced: boolean | null;
  bug_fixed: boolean | null;
  existing_tests_total: number | null;
  existing_tests_passed: number | null;
  existing_tests_failed: number | null;
  no_regressions: boolean | null;
  regression_count: number;
  new_static_findings: number;
  score: number | null;
  disposition: CandidateDisposition;
  created_at: string;
  completed_at: string | null;
}

export interface RepairSession {
  id: string;
  project_id: string;
  debugging_session_id: string | null;
  hypothesis_id: string | null;
  reproduction_session_id: string | null;
  status: RepairStatus;
  total_candidates: number;
  best_candidate_id: string | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  candidates?: PatchCandidate[];
}

export interface RepairSessionsListResponse {
  items: RepairSession[];
  total: number;
  offset: number;
  limit: number;
}

// ── Patch Verification (v0.8) ──────────────────────────────────────────────

export type VerificationDecision =
  | "verified"
  | "rejected"
  | "inconclusive"
  | "environment_failed"
  | "baseline_failed";

export type VerificationStatus =
  | "pending"
  | "running"
  | "baseline_failed"
  | "applying"
  | "testing"
  | "analyzing"
  | "comparing"
  | "verified"
  | "rejected"
  | "inconclusive"
  | "environment_failed";

export interface PatchVerification {
  id: string;
  candidate_id: string;
  session_id: string;
  project_id: string;
  status: VerificationStatus;
  error_message: string | null;

  // baseline
  baseline_reproduced: boolean | null;
  baseline_reproduction_evidence: string | null;
  baseline_tests_total: number;
  baseline_tests_passed: number;
  baseline_tests_failed: number;
  baseline_tests_error: number;
  baseline_tests_skipped: number;
  baseline_passing_ids: string[];
  baseline_failing_ids: string[];
  baseline_static_findings: number;

  // patch application
  patch_applied: boolean | null;
  patch_apply_error: string | null;

  // post-patch
  post_patch_reproduced: boolean | null;
  post_patch_reproduction_evidence: string | null;
  post_tests_total: number;
  post_tests_passed: number;
  post_tests_failed: number;
  post_tests_error: number;
  post_tests_skipped: number;
  post_passing_ids: string[];
  post_failing_ids: string[];
  post_static_findings: number;

  // comparison
  target_bug_fixed: boolean | null;
  newly_failing_ids: string[];
  recovered_ids: string[];
  regression_count: number;
  new_static_introduced: number;
  static_resolved: number;
  new_finding_ids: string[];
  resolved_finding_ids: string[];

  // execution metadata
  executor_type: string | null;
  schema_version: number;
  baseline_test_execution_status: string;
  baseline_static_analysis_status: string;
  baseline_finding_ids: string[];
  baseline_duration_seconds: number | null;
  post_test_execution_status: string;
  post_static_analysis_status: string;
  post_finding_ids: string[];
  post_duration_seconds: number | null;

  // security
  security_passed: boolean | null;
  security_issues: string[];

  // decision
  verification_score: number | null;
  verification_decision: VerificationDecision | null;
  decision_reasons: string[];
  evidence_summary: string | null;

  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

// ── GitHub Integration (v0.9) ──────────────────────────────────────────────

export interface GitHubRepository {
  id: string;
  project_id: string;
  owner: string;
  repo: string;
  github_id: number | null;
  default_branch: string;
  html_url: string;
  connected: boolean;
  created_at: string;
  updated_at: string;
}

export type DeliveryStatus =
  | "pending"
  | "preparing"
  | "final_verification"
  | "branch_created"
  | "committing"
  | "pushing"
  | "pr_created"
  | "completed"
  | "failed"
  | "aborted";

export interface GitHubDelivery {
  id: string;
  project_id: string;
  candidate_id: string;
  verification_id: string;
  owner: string;
  repo: string;
  base_branch: string;
  delivery_branch: string;
  commit_sha: string | null;
  pull_request_number: number | null;
  pull_request_url: string | null;
  verified_patch_hash: string;
  delivered_patch_hash: string | null;
  status: DeliveryStatus;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

// ── Autonomous Discovery (v1.1.0) ─────────────────────────────────────────

export interface DiscoveryRun {
  id: string;
  status: "running" | "completed" | "failed" | "cancelled";
  search_criteria: string | null;
  discovered_count: number;
  eligible_count: number;
  rejected_count: number;
  github_api_requests: number;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
  created_at: string;
}

export interface DiscoveryRunsListResponse {
  items: DiscoveryRun[];
  total: number;
  offset: number;
  limit: number;
}

export type EligibilityStatus =
  | "discovered"
  | "screening"
  | "eligible"
  | "rejected"
  | "blocked"
  | "queued"
  | "analyzing"
  | "completed"
  | "failed"
  | "paused";

export type SafetyClassification = "safe_candidate" | "low_risk" | "needs_review" | "blocked";

export interface RepositoryCandidate {
  id: string;
  github_repo_id: number;
  owner: string;
  name: string;
  full_name: string;
  html_url: string;
  stars: number;
  is_fork: boolean;
  is_archived: boolean;
  default_branch: string;
  primary_language: string | null;
  license_key: string | null;
  size_kb: number;
  open_issues: number;
  topics: string | null; // JSON array string
  description: string | null;
  last_updated_at: string | null;
  last_pushed_at: string | null;
  eligibility_status: EligibilityStatus;
  eligibility_score: number | null;
  rejection_reason: string | null;
  safety_classification: SafetyClassification | null;
  safety_detail: string | null;
  analysis_status: string | null;
  last_analyzed_commit: string | null;
  last_analyzed_at: string | null;
  discovered_at: string;
  created_at: string;
  updated_at: string;
}

export interface RepositoryCandidatesListResponse {
  items: RepositoryCandidate[];
  total: number;
  offset: number;
  limit: number;
}

export interface CandidateStatusCounts {
  counts: Record<string, number>;
}

export interface AutonomousRun {
  id: string;
  candidate_id: string;
  project_id: string | null;
  status: string;
  current_stage: string | null;
  commit_sha: string | null;
  ai_provider: string | null;
  ai_model: string | null;
  is_local_ai: boolean;
  static_findings_count: number;
  ai_hypotheses_count: number;
  validated_findings_count: number;
  rejected_findings_count: number;
  tests_generated: number;
  tests_executed: number;
  repairs_generated: number;
  repairs_verified: number;
  started_at: string | null;
  completed_at: string | null;
  error_code: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutonomousRunsListResponse {
  items: AutonomousRun[];
  total: number;
  offset: number;
  limit: number;
}

export interface AIStatus {
  provider: string;
  model: string;
  is_local: boolean;
  reachable: boolean;
  configured: boolean;
  model_available: boolean | null;
  error: string | null;
  capabilities: string[] | null;
  thinking_enabled?: boolean;
  language_analyzers?: string[];
  security_analysis_status?: string;
}

export interface SecurityFinding {
  id: string;
  project_id: string | null;
  analysis_id: string | null;
  title: string;
  status: string;
  vulnerability_class: string | null;
  evidence_tier: string;
  confidence: string;
  description: string;
  hypothesis: string | null;
  ai_analysis: string | null;
  impact: string | null;
  file_path: string | null;
  line: number | null;
  analyzer: string | null;
  rule_ids: string;
  observation_refs: string;
  asset: string | null;
  created_at: string;
}

export interface SecurityStatus {
  status: string;
  language_analyzers: Array<{
    language_id: string;
    display_name: string;
    capabilities: string[];
    extensions: string[];
  }>;
  rule_ids: string[];
  ai_provider: string;
  ai_model: string;
  ai_local: boolean;
  thinking_enabled: boolean;
  notes: string;
}

export interface DiscoverySettings {
  discovery_mode: string;
  discovery_interval_hours: number;
  discovery_min_stars: number;
  discovery_max_stars: number;
  discovery_languages: string;
  discovery_require_license: boolean;
  discovery_skip_forks: boolean;
  discovery_skip_archived: boolean;
  discovery_max_staleness_days: number;
  discovery_daily_repo_limit: number;
  discovery_max_concurrent: number;
  discovery_max_size_kb: number;
  discovery_excluded_topics: string;
  discovery_excluded_owners: string;
  safety_max_repo_size_kb: number;
  safety_max_file_count: number;
  safety_allow_docker_exec: boolean;
  safety_allow_sandbox_network: boolean;
  safety_allow_dep_install: boolean;
}
