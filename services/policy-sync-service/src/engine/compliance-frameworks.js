'use strict';

const COMPLIANCE_FRAMEWORKS = {
  SOC2: {
    id: 'SOC2',
    name: 'SOC 2 Type II',
    description: 'AICPA Trust Services Criteria for security, availability, processing integrity, confidentiality, and privacy',
    icon: 'shield-check',
    controls: {
      'CC6.1': 'Logical and Physical Access Controls',
      'CC6.2': 'Prior to Issuing System Credentials and Granting System Access',
      'CC6.3': 'Access Based on Authorization',
      'CC6.6': 'System Boundaries and Threat Protection',
      'CC6.7': 'Restricts Transmission, Movement, and Removal of Information',
      'CC6.8': 'Controls Against Unauthorized or Malicious Software',
      'CC7.1': 'Detect and Monitor Anomalies and Events',
      'CC7.2': 'Monitor System Components for Anomalies',
      'CC8.1': 'Changes to Infrastructure, Data, Software, and Procedures',
      'CC9.1': 'Risk Mitigation Activities'
    }
  },
  PCI_DSS: {
    id: 'PCI_DSS',
    name: 'PCI DSS v4.0',
    description: 'Payment Card Industry Data Security Standard for protecting cardholder data',
    icon: 'credit-card',
    controls: {
      '2.2': 'System Components Configured and Managed Securely',
      '3.5': 'Primary Account Number (PAN) Secured Wherever Stored',
      '7.1': 'Access to System Components and Data Restricted',
      '7.2': 'Access Appropriately Defined and Assigned',
      '7.3': 'Access to System Components and Data Managed via Access Control System',
      '8.1': 'Identification and Authentication for Users and Administrators',
      '8.2': 'User Identification and Related Accounts Managed',
      '8.2.4': 'Authentication Credential Rotation',
      '8.3': 'Strong Authentication for Users and Administrators',
      '8.6': 'Use of Application and System Accounts Managed',
      '10.1': 'Audit Trails Established and Active',
      '10.2': 'Audit Logs Record User Activities',
      '11.5': 'Network Intrusions and File Changes Detected and Responded To'
    }
  },
  NIST_800_53: {
    id: 'NIST_800_53',
    name: 'NIST 800-53 Rev 5',
    description: 'Security and Privacy Controls for Information Systems and Organizations',
    icon: 'landmark',
    controls: {
      'AC-2': 'Account Management',
      'AC-3': 'Access Enforcement',
      'AC-4': 'Information Flow Enforcement',
      'AC-6': 'Least Privilege',
      'AC-17': 'Remote Access',
      'AU-2': 'Event Logging',
      'AU-3': 'Content of Audit Records',
      'AU-6': 'Audit Record Review, Analysis, and Reporting',
      'CA-7': 'Continuous Monitoring',
      'CM-3': 'Configuration Change Control',
      'IA-2': 'Identification and Authentication (Organizational Users)',
      'IA-4': 'Identifier Management',
      'IA-5': 'Authenticator Management',
      'IA-8': 'Identification and Authentication (Non-Organizational Users)',
      'IR-4': 'Incident Handling',
      'SC-7': 'Boundary Protection',
      'SC-8': 'Transmission Confidentiality and Integrity',
      'SC-12': 'Cryptographic Key Establishment and Management',
      'SI-4': 'System Monitoring'
    }
  },
  ISO_27001: {
    id: 'ISO_27001',
    name: 'ISO 27001:2022',
    description: 'Information Security Management System requirements and Annex A controls',
    icon: 'globe',
    controls: {
      'A.5.15': 'Access Control',
      'A.5.16': 'Identity Management',
      'A.5.17': 'Authentication Information',
      'A.5.18': 'Access Rights',
      'A.5.23': 'Information Security for Cloud Services',
      'A.5.33': 'Protection of Records',
      'A.8.1': 'User Endpoint Devices',
      'A.8.2': 'Privileged Access Rights',
      'A.8.3': 'Information Access Restriction',
      'A.8.5': 'Secure Authentication',
      'A.8.9': 'Configuration Management',
      'A.8.15': 'Logging',
      'A.8.16': 'Monitoring Activities',
      'A.8.24': 'Use of Cryptography',
      'A.9.2.1': 'User Registration and De-registration',
      'A.9.2.6': 'Removal or Adjustment of Access Rights',
      'A.9.4.3': 'Password Management System'
    }
  },
  EU_AI_ACT: {
    id: 'EU_AI_ACT',
    name: 'EU AI Act',
    description: 'European Union regulation on artificial intelligence systems — effective August 2026',
    icon: 'brain',
    controls: {
      'Art.9': 'Risk Management System',
      'Art.10': 'Data and Data Governance',
      'Art.12': 'Record-Keeping and Traceability',
      'Art.13': 'Transparency and Information to Deployers',
      'Art.14': 'Human Oversight',
      'Art.15': 'Accuracy, Robustness, and Cybersecurity',
      'Art.17': 'Quality Management System',
      'Art.26': 'Obligations of Deployers',
      'Art.72': 'Monitoring and Reporting of Serious Incidents'
    }
  },
  MITRE_ATLAS: {
    id: 'MITRE_ATLAS',
    name: 'MITRE ATLAS',
    description: 'Adversarial Threat Landscape for AI Systems — tactics, techniques, and mitigations for ML/AI security',
    icon: 'target',
    controls: {
      'AML.T0002': 'Active Scanning — Reconnaissance of ML models and AI services',
      'AML.T0010': 'ML Supply Chain Compromise — Poisoned models, packages, or dependencies',
      'AML.T0010.001': 'Poison Training Data — Manipulate training datasets to embed backdoors',
      'AML.T0010.002': 'Poison ML Model — Compromise model integrity via supply chain',
      'AML.T0012': 'Exploit Public-Facing Application — Abuse over-privileged AI endpoints',
      'AML.T0012.001': 'Valid Accounts — Compromise shared or over-permissioned service accounts',
      'AML.T0014': 'Discover ML Model — Enumerate AI models and capabilities',
      'AML.T0024': 'Exfiltration via ML Inference API — Extract data through model queries',
      'AML.T0025': 'Exfiltration via Cyber Means — Steal credentials or data via leaked keys',
      'AML.T0029': 'Denial of ML Service — Disrupt AI service availability',
      'AML.T0034': 'Cost Harvesting — Exploit AI compute for unauthorized usage',
      'AML.T0040': 'ML Model Inference API Access — Unauthorized access to model endpoints',
      'AML.T0043': 'Establish Accounts — Create persistent access via unauthenticated agents',
      'AML.T0043.001': 'Compromise Agent Identity — Forge or tamper with agent credentials'
    }
  }
};

module.exports = { COMPLIANCE_FRAMEWORKS };
