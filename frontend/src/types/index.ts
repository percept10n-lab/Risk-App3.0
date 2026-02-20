// Common
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

// Asset
export interface Asset {
  id: string
  ip_address: string
  mac_address: string | null
  hostname: string | null
  vendor: string | null
  os_guess: string | null
  asset_type: string
  zone: string
  owner: string | null
  criticality: 'low' | 'medium' | 'high' | 'critical'
  data_types: string[]
  update_capability: string
  exposure: Record<string, boolean>
  tags: string[]
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
}

// Finding
export interface Finding {
  id: string
  asset_id: string
  run_id: string | null
  title: string
  description: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  category: string
  source_tool: string
  source_check: string
  cve_ids: string[]
  cwe_id: string | null
  cpe: string | null
  evidence_artifact_ids: string[]
  raw_output_snippet: string | null
  remediation: string | null
  exploitability_score: number | null
  exploitability_rationale: Record<string, any> | null
  status: 'open' | 'in_progress' | 'fixed' | 'accepted' | 'exception' | 'verified'
  dedupe_hash: string | null
  created_at: string
  updated_at: string
}

// Finding with enrichment data from API
export interface EnrichedFinding extends Finding {
  asset?: { id: string; hostname: string | null; ip_address: string } | null
  mitre_techniques?: Array<{ technique_id: string; technique_name: string; tactic: string }> | null
}

// Threat
export interface Threat {
  id: string
  asset_id: string | null
  title: string
  description: string
  threat_type: string
  source: 'rule' | 'manual' | 'ai_suggested'
  zone: string | null
  trust_boundary: string | null
  linked_finding_ids: string[]
  confidence: number
  rationale: string | null
  c4_level: 'system_context' | 'container' | 'component' | null
  stride_category_detail: string | null
  created_at: string
  updated_at: string
}

// Threat with enrichment data from API
export interface EnrichedThreat extends Threat {
  asset?: { id: string; hostname: string | null; ip_address: string } | null
  mitre_techniques?: Array<{ technique_id: string; technique_name: string; tactic: string }> | null
  linked_findings?: Array<{ id: string; title: string; severity: string }> | null
}

// Risk
export interface Risk {
  id: string
  asset_id: string
  threat_id: string | null
  finding_id: string | null
  scenario: string
  likelihood: string
  likelihood_rationale: string | null
  impact: string
  impact_rationale: string | null
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  confidentiality_impact: string
  integrity_impact: string
  availability_impact: string
  likelihood_factors: Record<string, any> | null
  impact_factors: Record<string, any> | null
  treatment: string | null
  treatment_plan: string | null
  treatment_measures: string[] | null
  treatment_owner: string | null
  treatment_due_date: string | null
  residual_risk_level: string | null
  status: string
  created_at: string
  updated_at: string
}

// MITRE
export interface MitreMapping {
  id: string
  finding_id: string | null
  threat_id: string | null
  technique_id: string
  technique_name: string
  tactic: string
  confidence: number
  source: string
  rationale: string | null
  created_at: string
  updated_at: string
}

// Run
export interface Run {
  id: string
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
  current_step: string | null
  steps_completed: string[]
  policy_id: string | null
  scope: Record<string, any>
  started_at: string | null
  completed_at: string | null
  triggered_by: string
  config_snapshot: Record<string, any>
  report_id: string | null
  created_at: string
}

// Policy
export interface Policy {
  id: string
  name: string
  description: string | null
  scope_allowlist: string[]
  scope_denylist: string[]
  action_allowlist: string[]
  rate_limits: Record<string, string>
  time_windows: Record<string, string>
  is_default: boolean
  created_at: string
  updated_at: string
}

// Scan Schedule
export interface ScanSchedule {
  id: string
  name: string
  schedule_type: 'interval' | 'cron'
  interval_hours: number | null
  cron_expression: string | null
  scope: Record<string, any> | null
  scan_type: 'full' | 'discovery' | 'vuln_only' | 'threat_only'
  enabled: boolean
  last_run_at: string | null
  next_run_at: string | null
  last_run_id: string | null
  created_at: string
  updated_at: string
}

// Audit Event
export interface AuditEvent {
  id: string
  run_id: string | null
  event_type: string
  entity_type: string
  entity_id: string
  actor: string
  action: string
  old_value: Record<string, any> | null
  new_value: Record<string, any> | null
  rationale: string | null
  timestamp: string
}
