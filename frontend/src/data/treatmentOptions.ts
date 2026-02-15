export interface TreatmentOption {
  id: string
  label: string
  description: string
  iso27001_controls: string[]
  mitre_mitigations: string[]
  relevance_tags: string[]
  treatment_type: 'mitigate' | 'transfer' | 'avoid' | 'accept'
}

export const TREATMENT_OPTIONS: TreatmentOption[] = [
  {
    id: 'access_control',
    label: 'Access Control',
    description: 'Implement role-based access control and least privilege principles',
    iso27001_controls: ['A.5.15', 'A.8.3', 'A.8.4'],
    mitre_mitigations: ['M1026', 'M1018'],
    relevance_tags: ['spoofing', 'elevation_of_privilege', 'information_disclosure', 'exposure_ssh', 'exposure_http'],
    treatment_type: 'mitigate',
  },
  {
    id: 'network_segmentation',
    label: 'Network Segmentation',
    description: 'Segment networks to isolate critical assets and limit lateral movement',
    iso27001_controls: ['A.8.22', 'A.8.20'],
    mitre_mitigations: ['M1030'],
    relevance_tags: ['tampering', 'information_disclosure', 'denial_of_service', 'zone_iot', 'zone_guest', 'zone_dmz'],
    treatment_type: 'mitigate',
  },
  {
    id: 'encryption',
    label: 'Encryption at Rest & Transit',
    description: 'Encrypt sensitive data at rest and in transit using strong algorithms',
    iso27001_controls: ['A.8.24', 'A.8.10'],
    mitre_mitigations: ['M1041'],
    relevance_tags: ['information_disclosure', 'tampering', 'exposure_tls', 'exposure_http'],
    treatment_type: 'mitigate',
  },
  {
    id: 'patch_management',
    label: 'Patch Management',
    description: 'Establish regular patching cycles and vulnerability remediation SLAs',
    iso27001_controls: ['A.8.8', 'A.8.19'],
    mitre_mitigations: ['M1051'],
    relevance_tags: ['vuln', 'elevation_of_privilege', 'tampering', 'exposure_http', 'exposure_ssh'],
    treatment_type: 'mitigate',
  },
  {
    id: 'mfa',
    label: 'Multi-Factor Authentication',
    description: 'Require MFA for all privileged and remote access',
    iso27001_controls: ['A.8.5', 'A.5.17'],
    mitre_mitigations: ['M1032'],
    relevance_tags: ['spoofing', 'elevation_of_privilege', 'exposure_ssh', 'exposure_http'],
    treatment_type: 'mitigate',
  },
  {
    id: 'logging_monitoring',
    label: 'Logging & Monitoring',
    description: 'Deploy centralized logging, SIEM integration, and alerting',
    iso27001_controls: ['A.8.15', 'A.8.16', 'A.8.17'],
    mitre_mitigations: ['M1057'],
    relevance_tags: ['repudiation', 'information_disclosure', 'tampering', 'denial_of_service'],
    treatment_type: 'mitigate',
  },
  {
    id: 'disable_service',
    label: 'Disable Unnecessary Service',
    description: 'Identify and disable unused services, ports, and protocols',
    iso27001_controls: ['A.8.9', 'A.8.20'],
    mitre_mitigations: ['M1042'],
    relevance_tags: ['exposure', 'denial_of_service', 'information_disclosure', 'exposure_dns', 'exposure_ssh'],
    treatment_type: 'mitigate',
  },
  {
    id: 'input_validation',
    label: 'Input Validation',
    description: 'Implement strict input validation and output encoding on all interfaces',
    iso27001_controls: ['A.8.26', 'A.8.28'],
    mitre_mitigations: ['M1054'],
    relevance_tags: ['tampering', 'elevation_of_privilege', 'exposure_http', 'vuln', 'misconfig'],
    treatment_type: 'mitigate',
  },
  {
    id: 'backup_recovery',
    label: 'Backup & Recovery',
    description: 'Maintain tested backups with defined RPO/RTO and offsite storage',
    iso27001_controls: ['A.8.13', 'A.8.14'],
    mitre_mitigations: ['M1053'],
    relevance_tags: ['denial_of_service', 'tampering', 'availability'],
    treatment_type: 'mitigate',
  },
  {
    id: 'security_awareness',
    label: 'Security Awareness Training',
    description: 'Regular security awareness and phishing simulation training for staff',
    iso27001_controls: ['A.6.3', 'A.7.2'],
    mitre_mitigations: ['M1017'],
    relevance_tags: ['spoofing', 'repudiation', 'information_disclosure'],
    treatment_type: 'mitigate',
  },
  {
    id: 'cyber_insurance',
    label: 'Cyber Insurance',
    description: 'Transfer residual risk through a cyber insurance policy',
    iso27001_controls: ['A.5.6'],
    mitre_mitigations: [],
    relevance_tags: ['denial_of_service', 'information_disclosure', 'tampering'],
    treatment_type: 'transfer',
  },
  {
    id: 'managed_soc',
    label: 'Managed SOC',
    description: 'Outsource security monitoring to a managed SOC provider',
    iso27001_controls: ['A.5.19', 'A.5.20'],
    mitre_mitigations: ['M1057'],
    relevance_tags: ['repudiation', 'information_disclosure', 'tampering', 'denial_of_service'],
    treatment_type: 'transfer',
  },
  {
    id: 'decommission_asset',
    label: 'Decommission Asset',
    description: 'Remove the asset from the network entirely to eliminate the risk',
    iso27001_controls: ['A.8.10', 'A.7.14'],
    mitre_mitigations: ['M1042'],
    relevance_tags: ['exposure', 'denial_of_service', 'elevation_of_privilege'],
    treatment_type: 'avoid',
  },
  {
    id: 'full_isolation',
    label: 'Full Isolation',
    description: 'Air-gap or fully isolate the asset from other network segments',
    iso27001_controls: ['A.8.22'],
    mitre_mitigations: ['M1030'],
    relevance_tags: ['information_disclosure', 'tampering', 'zone_iot', 'zone_dmz'],
    treatment_type: 'avoid',
  },
  {
    id: 'accept_document',
    label: 'Accept & Document',
    description: 'Formally accept the risk with documented rationale and review schedule',
    iso27001_controls: ['A.5.5', 'A.5.1'],
    mitre_mitigations: [],
    relevance_tags: [],
    treatment_type: 'accept',
  },
]

/**
 * Return treatment options filtered by treatment type and scored by relevance.
 * @param treatmentType - mitigate, transfer, avoid, accept
 * @param contextTags - tags from the risk's linked threat type, finding category, asset exposure keys, zone
 */
export function getContextualOptions(
  treatmentType: string,
  contextTags: string[] = [],
): TreatmentOption[] {
  const filtered = TREATMENT_OPTIONS.filter(
    (opt) => opt.treatment_type === treatmentType,
  )

  if (contextTags.length === 0) return filtered

  const tagSet = new Set(contextTags.map((t) => t.toLowerCase()))

  return [...filtered].sort((a, b) => {
    const scoreA = a.relevance_tags.filter((t) => tagSet.has(t)).length
    const scoreB = b.relevance_tags.filter((t) => tagSet.has(t)).length
    return scoreB - scoreA
  })
}
