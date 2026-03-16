# =============================================================================
# Outputs — Azure Container Apps Spoke
# =============================================================================

output "resource_group_name" {
  description = "Azure resource group name"
  value       = azurerm_resource_group.spoke.name
}

output "container_environment_name" {
  description = "Container Apps Environment name"
  value       = azurerm_container_app_environment.spoke.name
}

output "acr_login_server" {
  description = "ACR login server URL for pushing images"
  value       = azurerm_container_registry.spoke.login_server
}

output "relay_fqdn" {
  description = "Relay Container App FQDN (external)"
  value       = azurerm_container_app.relay.latest_revision_fqdn
}

output "relay_url" {
  description = "Relay URL for health checks"
  value       = "https://${azurerm_container_app.relay.latest_revision_fqdn}"
}

output "gateway_fqdns" {
  description = "Map of gateway names to external FQDNs"
  value       = { for k, v in azurerm_container_app.gateway : k => v.latest_revision_fqdn }
}

output "gateway_urls" {
  description = "Map of gateway names to external URLs"
  value       = { for k, v in azurerm_container_app.gateway : k => "https://${v.latest_revision_fqdn}" }
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for queries"
  value       = azurerm_log_analytics_workspace.spoke.id
}

# ─── Managed Identity ──────────────────────────────────────────────────────────

output "managed_identity_client_id" {
  description = "Client ID of the User-Assigned Managed Identity"
  value       = azurerm_user_assigned_identity.spoke.client_id
}

output "managed_identity_principal_id" {
  description = "Principal ID of the User-Assigned Managed Identity"
  value       = azurerm_user_assigned_identity.spoke.principal_id
}

# ─── VNET ──────────────────────────────────────────────────────────────────────

output "vnet_id" {
  description = "VNET ID (empty if VNET disabled)"
  value       = var.enable_vnet ? azurerm_virtual_network.spoke[0].id : ""
}

output "vnet_name" {
  description = "VNET name (empty if VNET disabled)"
  value       = var.enable_vnet ? azurerm_virtual_network.spoke[0].name : ""
}

# ─── Key Vault ─────────────────────────────────────────────────────────────────

output "keyvault_url" {
  description = "Key Vault URI (empty if Key Vault disabled)"
  value       = var.enable_keyvault ? azurerm_key_vault.spoke[0].vault_uri : ""
}

output "keyvault_name" {
  description = "Key Vault name (empty if Key Vault disabled)"
  value       = var.enable_keyvault ? azurerm_key_vault.spoke[0].name : ""
}

# ─── Summary ───────────────────────────────────────────────────────────────────

output "spoke_summary" {
  description = "Quick summary of the spoke deployment"
  value = {
    environment           = var.environment_name
    central_url           = var.central_url
    relay_url             = "https://${azurerm_container_app.relay.latest_revision_fqdn}/health"
    gateway_urls          = { for k, v in azurerm_container_app.gateway : k => "https://${v.latest_revision_fqdn}" }
    region                = var.azure_region
    managed_identity_id   = azurerm_user_assigned_identity.spoke.client_id
    vnet_enabled          = var.enable_vnet
    keyvault_enabled      = var.enable_keyvault
    keyvault_url          = var.enable_keyvault ? azurerm_key_vault.spoke[0].vault_uri : "disabled"
    mtls_enabled          = var.enable_mtls
    tenant_id             = var.tenant_id
    data_region           = var.data_region
  }
}
