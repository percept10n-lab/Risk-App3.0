import api from './client'
import type { PaginatedResponse, Asset, Finding, Threat, Risk, MitreMapping, Run, ScanSchedule } from '../types'

// Assets
export const assetsApi = {
  list: (params?: Record<string, any>) => api.get<PaginatedResponse<Asset>>('/assets', { params }),
  get: (id: string) => api.get<Asset>(`/assets/${id}`),
  create: (data: Partial<Asset>) => api.post<Asset>('/assets', data),
  update: (id: string, data: Partial<Asset>) => api.put<Asset>(`/assets/${id}`, data),
  delete: (id: string) => api.delete(`/assets/${id}`),
  deletePreview: (id: string) => api.get(`/assets/${id}/delete-preview`),
  override: (id: string, data: { field: string; value: any; rationale: string }) =>
    api.post(`/assets/${id}/override`, data),
  detectGateway: () => api.get('/assets/detect-gateway'),
  fingerprint: (data: { asset_id: string }) => api.post('/scan/fingerprint', data),
}

// Discovery
export const discoveryApi = {
  discover: (data: { subnet: string; timeout?: number }) => api.post('/scan/discover', data),
  nmapDiscover: (data: { network: string; timeout?: number }) => api.post('/scan/nmap-discover', data),
}

// Findings
export const findingsApi = {
  list: (params?: Record<string, any>) => api.get<PaginatedResponse<Finding>>('/findings', { params }),
  get: (id: string) => api.get<Finding>(`/findings/${id}`),
  create: (data: Partial<Finding>) => api.post<Finding>('/findings', data),
  update: (id: string, data: Partial<Finding>) => api.put<Finding>(`/findings/${id}`, data),
  override: (id: string, data: { field: string; value: any; rationale: string }) =>
    api.post(`/findings/${id}/override`, data),
  stats: () => api.get('/findings/stats'),
}

// Threats
export const threatsApi = {
  list: (params?: Record<string, any>) => api.get<PaginatedResponse<Threat>>('/threats', { params }),
  get: (id: string) => api.get<Threat>(`/threats/${id}`),
  create: (data: Partial<Threat>) => api.post<Threat>('/threats', data),
  update: (id: string, data: Partial<Threat>) => api.put<Threat>(`/threats/${id}`, data),
  delete: (id: string) => api.delete(`/threats/${id}`),
  generate: (data?: { asset_id?: string; run_id?: string }) =>
    api.post('/threats/generate', data || {}),
  zoneAnalysis: (data: { zone: string; run_id?: string }) =>
    api.post('/threats/zone-analysis', data),
  stats: () => api.get('/threats/stats'),
}

// Vuln Scan
export const vulnScanApi = {
  scan: (data?: { asset_id?: string; run_id?: string; timeout?: number }) =>
    api.post('/findings/scan', data || {}),
}

// Risks
export const risksApi = {
  list: (params?: Record<string, any>) => api.get<PaginatedResponse<Risk>>('/risks', { params }),
  get: (id: string) => api.get<Risk>(`/risks/${id}`),
  getFullContext: (id: string) => api.get(`/risks/${id}/full-context`),
  matrix: () => api.get('/risks/matrix'),
  analyze: (data?: { asset_id?: string; run_id?: string }) => api.post('/risks/analyze', data || {}),
  create: (data: Partial<Risk>) => api.post<Risk>('/risks', data),
  update: (id: string, data: Partial<Risk>) => api.put<Risk>(`/risks/${id}`, data),
  treat: (id: string, data: any) => api.post(`/risks/${id}/treatment`, data),
  override: (id: string, data: { field: string; value: any; rationale: string }) =>
    api.post(`/risks/${id}/override`, data),
  stats: () => api.get('/risks/stats'),
}

// MITRE
export const mitreApi = {
  listMappings: (params?: Record<string, any>) => api.get<PaginatedResponse<MitreMapping>>('/mitre/mappings', { params }),
  createMapping: (data: Partial<MitreMapping>) => api.post<MitreMapping>('/mitre/mappings', data),
  exportLayer: () => api.get('/mitre/layer-export'),
}

// Runs
export const runsApi = {
  list: (params?: Record<string, any>) => api.get<PaginatedResponse<Run>>('/runs', { params }),
  get: (id: string) => api.get<Run>(`/runs/${id}`),
  create: (data?: any) => api.post<Run>('/runs', data || {}),
  pause: (id: string) => api.post(`/runs/${id}/pause`),
  resume: (id: string) => api.post(`/runs/${id}/resume`),
  cancel: (id: string) => api.post(`/runs/${id}/cancel`),
  executeStep: (stepName: string) => api.post(`/runs/step/${stepName}`),
}

// Reports
export const reportsApi = {
  summary: () => api.get('/reports/summary'),
  generate: (data: { report_type: string; run_id?: string; title?: string }) => api.post('/reports/generate', data),
  get: (id: string) => api.get(`/reports/${id}`),
  download: (id: string) => api.get(`/reports/${id}/download`, { responseType: 'blob' }),
}

// Pentest
export const pentestApi = {
  listActions: () => api.get('/pentest/actions'),
  execute: (data: { action_id: string; target: string; run_id?: string; params?: Record<string, any> }) =>
    api.post('/pentest/execute', data),
  history: (params?: Record<string, any>) => api.get('/pentest/history', { params }),
  verifyScope: (data: { target: string }) => api.post('/pentest/verify-scope', data),
}

// Copilot
export const copilotApi = {
  triage: (findingIds: string[]) => api.post('/copilot/triage', { finding_ids: findingIds }),
  remediation: (findingId: string, context?: any) => api.post('/copilot/remediation', { finding_id: findingId, context }),
  investigate: (findingId: string) => api.post('/copilot/investigate', { finding_id: findingId }),
  gather: (findingId: string) => api.post('/copilot/gather', { finding_id: findingId }),
  executeRemediation: (data: { finding_id: string; action: string; params?: any }) =>
    api.post('/copilot/execute-remediation', data),
  verify: (data: { finding_id: string; action_id: string; target: string }) =>
    api.post('/copilot/verify', data),
  mitreSuggest: (findingId: string) => api.post('/copilot/mitre-suggest', null, { params: { finding_id: findingId } }),
  narrative: (data: any) => api.post('/copilot/narrative', data),
  suggestions: () => api.get('/copilot/suggestions'),
  chat: (message: string, conversation: Array<{ role: string; content: string }>) =>
    api.post('/copilot/chat', { message, conversation }),
  status: () => api.get('/copilot/status'),
}

// Drift
export const driftApi = {
  changes: (params?: { zone?: string }) => api.get('/drift/changes', { params }),
  alerts: (params?: { zone?: string }) => api.get('/drift/alerts', { params }),
  baselines: (params?: { zone?: string }) => api.get('/drift/baselines', { params }),
  createBaseline: (data: { zone: string; baseline_type?: string; run_id?: string }) =>
    api.post('/drift/baseline', data),
}

// Settings
export const settingsApi = {
  getPolicy: () => api.get('/settings/policy'),
  updatePolicy: (data: any) => api.put('/settings/policy', data),
  getAiConfig: () => api.get('/settings/ai-config'),
  updateAiConfig: (data: any) => api.put('/settings/ai-config', null, { params: data }),
}

// Health
export const healthApi = {
  check: () => api.get('/health'),
}

// Nmap Scanner
export const nmapApi = {
  scan: (data: { target: string; nmap_args?: string; timeout?: number; auto_pipeline?: boolean }) =>
    api.post('/nmap/scan', data),
  results: (params?: Record<string, any>) => api.get('/nmap/results', { params }),
  status: (runId: string) => api.get(`/nmap/status/${runId}`),
}

// Vuln Management
export const vulnMgmtApi = {
  metrics: () => api.get('/vulns/metrics'),
  enrichedFinding: (findingId: string) => api.get(`/vulns/finding/${findingId}/enriched`),
  syncFromFindings: () => api.post('/vulns/create-from-findings'),
}

// Intel
export const intelApi = {
  summary: (days: number = 7) => api.get('/intel/summary', { params: { days } }),
  dailyBrief: () => api.get('/intel/daily-brief'),
  news: (force?: boolean) => api.get('/intel/news', { params: force ? { force: true } : undefined }),
  lookupCve: (cveId: string) => api.get(`/intel/cve/${cveId}`),
  lookupIp: (ip: string) => api.get(`/intel/ip/${ip}`),
  searchIoc: (indicator: string) => api.get(`/intel/ioc/${indicator}`),
  lookupCerts: (domain: string) => api.get(`/intel/certs/${domain}`),
  feedStatus: () => api.get('/intel/feed-status'),
}

// Schedules
export const schedulesApi = {
  list: () => api.get<ScanSchedule[]>('/schedules'),
  get: (id: string) => api.get<ScanSchedule>(`/schedules/${id}`),
  create: (data: Partial<ScanSchedule>) => api.post<ScanSchedule>('/schedules', data),
  update: (id: string, data: Partial<ScanSchedule>) => api.put<ScanSchedule>(`/schedules/${id}`, data),
  delete: (id: string) => api.delete(`/schedules/${id}`),
  toggle: (id: string) => api.post(`/schedules/${id}/toggle`),
  runNow: (id: string) => api.post(`/schedules/${id}/run-now`),
}
