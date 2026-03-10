# Enhanced OPA Policy with Capability-Based Access Control
# This implements the missing "trust gate" between discovery and issuance

package workload

import future.keywords.if
import future.keywords.in

# =============================================================================
# Main Authorization Decision
# =============================================================================

# Default deny
default allow = false

# Allow if all conditions are met
allow if {
    # 1. Workload is verified
    input.nhi.verified == true
    
    # 2. Workload has sufficient security score
    input.nhi.security_score >= 70
    
    # 3. Trust domain is valid
    trust_domain_valid
    
    # 4. Capability is allowed for this workload
    capability_allowed
    
    # 5. Context constraints are met
    context_allowed
}

# =============================================================================
# Trust Domain Validation
# =============================================================================

default trust_domain_valid = false

trust_domain_valid if {
    # Same trust domain
    input.nhi.trust_domain == "company.com"
}

trust_domain_valid if {
    # Explicit cross-domain trust
    allowed_domains := {"company.com", "partner.com"}
    input.nhi.trust_domain in allowed_domains
}

# =============================================================================
# Capability-Based Access Control
# =============================================================================

# Define capability hierarchy
capability_allowed if {
    # Token exchange - basic capability
    input.request.capability == "token:exchange"
    workload_can_exchange_tokens
}

capability_allowed if {
    # Token issue - elevated capability
    input.request.capability == "token:issue"
    input.nhi.security_score >= 90
}

capability_allowed if {
    # AWS credential issuance
    input.request.capability == "credential:issue:aws"
    workload_can_issue_credentials
}

capability_allowed if {
    # GCP credential issuance
    input.request.capability == "credential:issue:gcp"
    workload_can_issue_credentials
}

capability_allowed if {
    # Azure credential issuance
    input.request.capability == "credential:issue:azure"
    workload_can_issue_credentials
}

capability_allowed if {
    # Secret read
    input.request.capability == "secret:read"
    workload_can_read_secrets
}

capability_allowed if {
    # AI-specific capabilities
    input.request.capability in ["model:invoke", "model:train"]
    input.nhi.is_ai_agent == true
    ai_agent_allowed
}

capability_allowed if {
    # MCP-specific capabilities
    input.request.capability in ["mcp:connect", "mcp:query", "mcp:execute"]
    input.nhi.is_mcp_server == true
    mcp_server_allowed
}

# =============================================================================
# Token Exchange Rules
# =============================================================================

workload_can_exchange_tokens if {
    # Verified workloads can exchange tokens
    input.nhi.verified == true
    input.nhi.security_score >= 70
}

# =============================================================================
# Credential Issuance Rules
# =============================================================================

workload_can_issue_credentials if {
    # Only high-trust workloads can issue cloud credentials
    input.nhi.verified == true
    input.nhi.security_score >= 80
    input.nhi.environment == "production"
}

# =============================================================================
# Secret Access Rules
# =============================================================================

workload_can_read_secrets if {
    # Verified workloads can read secrets
    input.nhi.verified == true
    input.nhi.security_score >= 75
}

# =============================================================================
# AI Agent Specific Rules
# =============================================================================

ai_agent_allowed if {
    # AI agents can invoke models
    input.request.capability == "model:invoke"
    input.nhi.security_score >= 75
}

ai_agent_allowed if {
    # AI agents can train models (high-trust only)
    input.request.capability == "model:train"
    input.nhi.security_score >= 85
    input.nhi.environment == "production"
}

# =============================================================================
# MCP Server Specific Rules
# =============================================================================

mcp_server_allowed if {
    # MCP servers can connect
    input.request.capability == "mcp:connect"
    input.nhi.security_score >= 70
}

mcp_server_allowed if {
    # MCP servers can query
    input.request.capability == "mcp:query"
    input.nhi.security_score >= 70
}

mcp_server_allowed if {
    # MCP servers can execute (high-trust only)
    input.request.capability == "mcp:execute"
    input.nhi.security_score >= 85
}

# =============================================================================
# Context Constraints
# =============================================================================

context_allowed if {
    # Basic context validation
    input.request.time
}

# =============================================================================
# Query APIs (for capability discovery)
# =============================================================================

# Get all capabilities a workload has
capabilities contains capability if {
    input.nhi.verified == true
    input.nhi.security_score >= 70
    capability := "token:exchange"
}

capabilities contains capability if {
    input.nhi.verified == true
    input.nhi.security_score >= 80
    input.nhi.environment == "production"
    capability := "credential:issue:aws"
}

capabilities contains capability if {
    input.nhi.is_ai_agent == true
    input.nhi.security_score >= 75
    capability := "model:invoke"
}

capabilities contains capability if {
    input.nhi.is_mcp_server == true
    input.nhi.security_score >= 70
    capability := "mcp:connect"
}

# =============================================================================
# Audit Logging Support
# =============================================================================

# Track policy decisions for audit
decision := {
    "allowed": allow,
    "workload": input.nhi.spiffe_id,
    "capability": input.request.capability,
    "timestamp": time.now_ns(),
    "security_score": input.nhi.security_score,
    "verified": input.nhi.verified,
    "reason": deny_reason
}

# Provide denial reasons
deny_reason := "Workload not verified" if {
    not input.nhi.verified
}

deny_reason := "Insufficient security score" if {
    input.nhi.verified
    input.nhi.security_score < 70
}

deny_reason := "Trust domain not valid" if {
    input.nhi.verified
    input.nhi.security_score >= 70
    not trust_domain_valid
}

deny_reason := "Capability not allowed" if {
    input.nhi.verified
    input.nhi.security_score >= 70
    trust_domain_valid
    not capability_allowed
}

deny_reason := "Context constraints not met" if {
    input.nhi.verified
    input.nhi.security_score >= 70
    trust_domain_valid
    capability_allowed
    not context_allowed
}

deny_reason := "Access granted" if allow
