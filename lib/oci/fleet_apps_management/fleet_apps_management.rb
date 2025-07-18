# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20250228

module OCI
  module FleetAppsManagement
    # Module containing models for requests made to, and responses received from,
    # OCI FleetAppsManagement services
    module Models
    end
  end
end

# Require models
require 'oci/fleet_apps_management/models/action_group'
require 'oci/fleet_apps_management/models/action_group_based_user_action_details'
require 'oci/fleet_apps_management/models/action_group_details'
require 'oci/fleet_apps_management/models/action_type'
require 'oci/fleet_apps_management/models/activity_resource_target'
require 'oci/fleet_apps_management/models/announcement_collection'
require 'oci/fleet_apps_management/models/announcement_sort_by'
require 'oci/fleet_apps_management/models/announcement_summary'
require 'oci/fleet_apps_management/models/api_based_execution_details'
require 'oci/fleet_apps_management/models/artifact_details'
require 'oci/fleet_apps_management/models/associated_fleet_credential_details'
require 'oci/fleet_apps_management/models/associated_fleet_property_details'
require 'oci/fleet_apps_management/models/associated_fleet_resource_details'
require 'oci/fleet_apps_management/models/associated_local_task_details'
require 'oci/fleet_apps_management/models/associated_scheduler_definition'
require 'oci/fleet_apps_management/models/associated_shared_task_details'
require 'oci/fleet_apps_management/models/associated_task_details'
require 'oci/fleet_apps_management/models/catalog_content_details'
require 'oci/fleet_apps_management/models/catalog_git_result_config'
require 'oci/fleet_apps_management/models/catalog_git_source_config'
require 'oci/fleet_apps_management/models/catalog_item'
require 'oci/fleet_apps_management/models/catalog_item_collection'
require 'oci/fleet_apps_management/models/catalog_item_sort_by'
require 'oci/fleet_apps_management/models/catalog_item_summary'
require 'oci/fleet_apps_management/models/catalog_listing_version_criteria_enum'
require 'oci/fleet_apps_management/models/catalog_marketplace_source_config'
require 'oci/fleet_apps_management/models/catalog_par_result_config'
require 'oci/fleet_apps_management/models/catalog_par_source_config'
require 'oci/fleet_apps_management/models/catalog_result_payload'
require 'oci/fleet_apps_management/models/catalog_source_payload'
require 'oci/fleet_apps_management/models/catalog_source_template_config'
require 'oci/fleet_apps_management/models/catalog_template_result_config'
require 'oci/fleet_apps_management/models/change_catalog_item_compartment_details'
require 'oci/fleet_apps_management/models/change_fleet_compartment_details'
require 'oci/fleet_apps_management/models/change_patch_compartment_details'
require 'oci/fleet_apps_management/models/change_platform_configuration_compartment_details'
require 'oci/fleet_apps_management/models/change_property_compartment_details'
require 'oci/fleet_apps_management/models/change_provision_compartment_details'
require 'oci/fleet_apps_management/models/change_runbook_compartment_details'
require 'oci/fleet_apps_management/models/change_task_record_compartment_details'
require 'oci/fleet_apps_management/models/check_resource_tagging_details'
require 'oci/fleet_apps_management/models/clone_catalog_item_details'
require 'oci/fleet_apps_management/models/compliance_detail_policy'
require 'oci/fleet_apps_management/models/compliance_detail_product'
require 'oci/fleet_apps_management/models/compliance_detail_resource'
require 'oci/fleet_apps_management/models/compliance_detail_target'
require 'oci/fleet_apps_management/models/compliance_level'
require 'oci/fleet_apps_management/models/compliance_patch_detail'
require 'oci/fleet_apps_management/models/compliance_policy'
require 'oci/fleet_apps_management/models/compliance_policy_collection'
require 'oci/fleet_apps_management/models/compliance_policy_rule'
require 'oci/fleet_apps_management/models/compliance_policy_rule_collection'
require 'oci/fleet_apps_management/models/compliance_policy_rule_sort_by'
require 'oci/fleet_apps_management/models/compliance_policy_rule_summary'
require 'oci/fleet_apps_management/models/compliance_policy_sort_by'
require 'oci/fleet_apps_management/models/compliance_policy_summary'
require 'oci/fleet_apps_management/models/compliance_record'
require 'oci/fleet_apps_management/models/compliance_record_aggregation'
require 'oci/fleet_apps_management/models/compliance_record_aggregation_collection'
require 'oci/fleet_apps_management/models/compliance_record_collection'
require 'oci/fleet_apps_management/models/compliance_record_dimension'
require 'oci/fleet_apps_management/models/compliance_record_sort_by'
require 'oci/fleet_apps_management/models/compliance_record_summary'
require 'oci/fleet_apps_management/models/compliance_report'
require 'oci/fleet_apps_management/models/compliance_report_patch_detail'
require 'oci/fleet_apps_management/models/compliance_report_product'
require 'oci/fleet_apps_management/models/compliance_report_resource'
require 'oci/fleet_apps_management/models/compliance_report_target'
require 'oci/fleet_apps_management/models/compliance_rule_severity'
require 'oci/fleet_apps_management/models/compliance_state'
require 'oci/fleet_apps_management/models/component_properties'
require 'oci/fleet_apps_management/models/condition'
require 'oci/fleet_apps_management/models/config_association_details'
require 'oci/fleet_apps_management/models/config_category_details'
require 'oci/fleet_apps_management/models/config_file_details'
require 'oci/fleet_apps_management/models/confirm_targets_details'
require 'oci/fleet_apps_management/models/content_details'
require 'oci/fleet_apps_management/models/create_catalog_item_details'
require 'oci/fleet_apps_management/models/create_compliance_policy_rule_details'
require 'oci/fleet_apps_management/models/create_fleet_credential_details'
require 'oci/fleet_apps_management/models/create_fleet_details'
require 'oci/fleet_apps_management/models/create_fleet_property_details'
require 'oci/fleet_apps_management/models/create_fleet_resource_details'
require 'oci/fleet_apps_management/models/create_maintenance_window_details'
require 'oci/fleet_apps_management/models/create_onboarding_details'
require 'oci/fleet_apps_management/models/create_patch_details'
require 'oci/fleet_apps_management/models/create_platform_configuration_details'
require 'oci/fleet_apps_management/models/create_property_details'
require 'oci/fleet_apps_management/models/create_provision_details'
require 'oci/fleet_apps_management/models/create_runbook_details'
require 'oci/fleet_apps_management/models/create_runbook_version_details'
require 'oci/fleet_apps_management/models/create_scheduler_definition_details'
require 'oci/fleet_apps_management/models/create_task_record_details'
require 'oci/fleet_apps_management/models/credential_config_category_details'
require 'oci/fleet_apps_management/models/credential_details'
require 'oci/fleet_apps_management/models/credential_entity_specific_details'
require 'oci/fleet_apps_management/models/custom_schedule'
require 'oci/fleet_apps_management/models/dependent_patch_details'
require 'oci/fleet_apps_management/models/deployed_resource_details'
require 'oci/fleet_apps_management/models/details'
require 'oci/fleet_apps_management/models/discovered_target'
require 'oci/fleet_apps_management/models/dynamic_resource_selection'
require 'oci/fleet_apps_management/models/enable_latest_policy_details'
require 'oci/fleet_apps_management/models/entity_execution_details'
require 'oci/fleet_apps_management/models/environment_config_category_details'
require 'oci/fleet_apps_management/models/environment_fleet_details'
require 'oci/fleet_apps_management/models/execution'
require 'oci/fleet_apps_management/models/execution_collection'
require 'oci/fleet_apps_management/models/execution_details'
require 'oci/fleet_apps_management/models/execution_summary'
require 'oci/fleet_apps_management/models/execution_workflow_details'
require 'oci/fleet_apps_management/models/export_compliance_report_details'
require 'oci/fleet_apps_management/models/file_input_argument'
require 'oci/fleet_apps_management/models/file_task_argument'
require 'oci/fleet_apps_management/models/fleet'
require 'oci/fleet_apps_management/models/fleet_based_action_group'
require 'oci/fleet_apps_management/models/fleet_based_action_group_details'
require 'oci/fleet_apps_management/models/fleet_collection'
require 'oci/fleet_apps_management/models/fleet_credential'
require 'oci/fleet_apps_management/models/fleet_credential_collection'
require 'oci/fleet_apps_management/models/fleet_credential_entity_specific_details'
require 'oci/fleet_apps_management/models/fleet_credential_sort_by'
require 'oci/fleet_apps_management/models/fleet_credential_summary'
require 'oci/fleet_apps_management/models/fleet_details'
require 'oci/fleet_apps_management/models/fleet_product_collection'
require 'oci/fleet_apps_management/models/fleet_product_summary'
require 'oci/fleet_apps_management/models/fleet_property'
require 'oci/fleet_apps_management/models/fleet_property_collection'
require 'oci/fleet_apps_management/models/fleet_property_sort_by'
require 'oci/fleet_apps_management/models/fleet_property_summary'
require 'oci/fleet_apps_management/models/fleet_resource'
require 'oci/fleet_apps_management/models/fleet_resource_collection'
require 'oci/fleet_apps_management/models/fleet_resource_sort_by'
require 'oci/fleet_apps_management/models/fleet_resource_summary'
require 'oci/fleet_apps_management/models/fleet_sort_by'
require 'oci/fleet_apps_management/models/fleet_summary'
require 'oci/fleet_apps_management/models/fleet_target'
require 'oci/fleet_apps_management/models/fleet_target_collection'
require 'oci/fleet_apps_management/models/fleet_target_summary'
require 'oci/fleet_apps_management/models/generate_compliance_report_details'
require 'oci/fleet_apps_management/models/generic_artifact'
require 'oci/fleet_apps_management/models/generic_artifact_details'
require 'oci/fleet_apps_management/models/generic_fleet_details'
require 'oci/fleet_apps_management/models/group'
require 'oci/fleet_apps_management/models/group_fleet_details'
require 'oci/fleet_apps_management/models/input_argument'
require 'oci/fleet_apps_management/models/input_file_content_details'
require 'oci/fleet_apps_management/models/input_file_object_storage_bucket_content_details'
require 'oci/fleet_apps_management/models/input_parameter'
require 'oci/fleet_apps_management/models/instance_summary'
require 'oci/fleet_apps_management/models/inventory_record'
require 'oci/fleet_apps_management/models/inventory_record_collection'
require 'oci/fleet_apps_management/models/inventory_record_component'
require 'oci/fleet_apps_management/models/inventory_record_patch_details'
require 'oci/fleet_apps_management/models/inventory_record_property'
require 'oci/fleet_apps_management/models/inventory_record_summary'
require 'oci/fleet_apps_management/models/inventory_resource_collection'
require 'oci/fleet_apps_management/models/inventory_resource_sort_by'
require 'oci/fleet_apps_management/models/inventory_resource_summary'
require 'oci/fleet_apps_management/models/job_activity'
require 'oci/fleet_apps_management/models/job_execution_details'
require 'oci/fleet_apps_management/models/job_status'
require 'oci/fleet_apps_management/models/key_encryption_credential_details'
require 'oci/fleet_apps_management/models/lifecycle_operation_config_category_details'
require 'oci/fleet_apps_management/models/maintenance_window'
require 'oci/fleet_apps_management/models/maintenance_window_collection'
require 'oci/fleet_apps_management/models/maintenance_window_schedule'
require 'oci/fleet_apps_management/models/maintenance_window_sort_by'
require 'oci/fleet_apps_management/models/maintenance_window_summary'
require 'oci/fleet_apps_management/models/manage_job_execution_details'
require 'oci/fleet_apps_management/models/manage_settings_details'
require 'oci/fleet_apps_management/models/managed_entity'
require 'oci/fleet_apps_management/models/managed_entity_aggregation'
require 'oci/fleet_apps_management/models/managed_entity_aggregation_collection'
require 'oci/fleet_apps_management/models/managed_entity_dimension'
require 'oci/fleet_apps_management/models/manual_resource_selection'
require 'oci/fleet_apps_management/models/notification_preference'
require 'oci/fleet_apps_management/models/object_storage_bucket_config_file_details'
require 'oci/fleet_apps_management/models/object_storage_bucket_content_details'
require 'oci/fleet_apps_management/models/onboarding'
require 'oci/fleet_apps_management/models/onboarding_collection'
require 'oci/fleet_apps_management/models/onboarding_policy_collection'
require 'oci/fleet_apps_management/models/onboarding_policy_summary'
require 'oci/fleet_apps_management/models/onboarding_summary'
require 'oci/fleet_apps_management/models/operation_runbook'
require 'oci/fleet_apps_management/models/operation_status'
require 'oci/fleet_apps_management/models/operation_type'
require 'oci/fleet_apps_management/models/os_type'
require 'oci/fleet_apps_management/models/outcome'
require 'oci/fleet_apps_management/models/output_variable_details'
require 'oci/fleet_apps_management/models/output_variable_input_argument'
require 'oci/fleet_apps_management/models/output_variable_mapping'
require 'oci/fleet_apps_management/models/patch'
require 'oci/fleet_apps_management/models/patch_collection'
require 'oci/fleet_apps_management/models/patch_file_content_details'
require 'oci/fleet_apps_management/models/patch_file_object_storage_bucket_content_details'
require 'oci/fleet_apps_management/models/patch_level_selection_details'
require 'oci/fleet_apps_management/models/patch_name_selection_details'
require 'oci/fleet_apps_management/models/patch_product'
require 'oci/fleet_apps_management/models/patch_release_date_selection_details'
require 'oci/fleet_apps_management/models/patch_selection_details'
require 'oci/fleet_apps_management/models/patch_severity'
require 'oci/fleet_apps_management/models/patch_sort_by'
require 'oci/fleet_apps_management/models/patch_summary'
require 'oci/fleet_apps_management/models/patch_type'
require 'oci/fleet_apps_management/models/patch_type_config_category_details'
require 'oci/fleet_apps_management/models/pause_details'
require 'oci/fleet_apps_management/models/plain_text_credential_details'
require 'oci/fleet_apps_management/models/platform_configuration'
require 'oci/fleet_apps_management/models/platform_configuration_collection'
require 'oci/fleet_apps_management/models/platform_configuration_sort_by'
require 'oci/fleet_apps_management/models/platform_configuration_summary'
require 'oci/fleet_apps_management/models/platform_specific_artifact'
require 'oci/fleet_apps_management/models/platform_specific_artifact_details'
require 'oci/fleet_apps_management/models/preferences'
require 'oci/fleet_apps_management/models/previous_task_instance_details'
require 'oci/fleet_apps_management/models/previous_task_instance_run_on_details'
require 'oci/fleet_apps_management/models/product_config_category_details'
require 'oci/fleet_apps_management/models/product_fleet_details'
require 'oci/fleet_apps_management/models/product_sort_by'
require 'oci/fleet_apps_management/models/product_stack_as_product_sub_category_details'
require 'oci/fleet_apps_management/models/product_stack_config_category_details'
require 'oci/fleet_apps_management/models/product_stack_generic_sub_category_details'
require 'oci/fleet_apps_management/models/product_stack_sub_category_details'
require 'oci/fleet_apps_management/models/product_version_details'
require 'oci/fleet_apps_management/models/properties'
require 'oci/fleet_apps_management/models/property'
require 'oci/fleet_apps_management/models/property_collection'
require 'oci/fleet_apps_management/models/property_sort_by'
require 'oci/fleet_apps_management/models/property_summary'
require 'oci/fleet_apps_management/models/provision'
require 'oci/fleet_apps_management/models/provision_collection'
require 'oci/fleet_apps_management/models/provision_summary'
require 'oci/fleet_apps_management/models/publish_runbook_details'
require 'oci/fleet_apps_management/models/request_resource_validation_details'
require 'oci/fleet_apps_management/models/request_target_discovery_details'
require 'oci/fleet_apps_management/models/resource_collection'
require 'oci/fleet_apps_management/models/resource_credential_entity_specific_details'
require 'oci/fleet_apps_management/models/resource_selection'
require 'oci/fleet_apps_management/models/resource_summary'
require 'oci/fleet_apps_management/models/resource_tag_check_details'
require 'oci/fleet_apps_management/models/resource_tag_enablement_info'
require 'oci/fleet_apps_management/models/rollback_workflow_details'
require 'oci/fleet_apps_management/models/rule'
require 'oci/fleet_apps_management/models/run_on_details'
require 'oci/fleet_apps_management/models/runbook'
require 'oci/fleet_apps_management/models/runbook_collection'
require 'oci/fleet_apps_management/models/runbook_sort_by'
require 'oci/fleet_apps_management/models/runbook_summary'
require 'oci/fleet_apps_management/models/runbook_version'
require 'oci/fleet_apps_management/models/runbook_version_collection'
require 'oci/fleet_apps_management/models/runbook_version_summary'
require 'oci/fleet_apps_management/models/schedule'
require 'oci/fleet_apps_management/models/schedule_instance_run_on_details'
require 'oci/fleet_apps_management/models/scheduled_fleet_collection'
require 'oci/fleet_apps_management/models/scheduled_fleet_summary'
require 'oci/fleet_apps_management/models/scheduler_definition'
require 'oci/fleet_apps_management/models/scheduler_definition_collection'
require 'oci/fleet_apps_management/models/scheduler_definition_summary'
require 'oci/fleet_apps_management/models/scheduler_execution_collection'
require 'oci/fleet_apps_management/models/scheduler_execution_summary'
require 'oci/fleet_apps_management/models/scheduler_job'
require 'oci/fleet_apps_management/models/scheduler_job_aggregation'
require 'oci/fleet_apps_management/models/scheduler_job_aggregation_collection'
require 'oci/fleet_apps_management/models/scheduler_job_collection'
require 'oci/fleet_apps_management/models/scheduler_job_dimension'
require 'oci/fleet_apps_management/models/scheduler_job_summary'
require 'oci/fleet_apps_management/models/scope'
require 'oci/fleet_apps_management/models/script_based_execution_details'
require 'oci/fleet_apps_management/models/selection'
require 'oci/fleet_apps_management/models/selection_criteria'
require 'oci/fleet_apps_management/models/self_hosted_instance_config_category_details'
require 'oci/fleet_apps_management/models/self_hosted_instance_run_on_details'
require 'oci/fleet_apps_management/models/set_default_runbook_details'
require 'oci/fleet_apps_management/models/sort_by'
require 'oci/fleet_apps_management/models/sort_order'
require 'oci/fleet_apps_management/models/step_based_user_action_details'
require 'oci/fleet_apps_management/models/step_collection'
require 'oci/fleet_apps_management/models/step_summary'
require 'oci/fleet_apps_management/models/string_input_argument'
require 'oci/fleet_apps_management/models/string_task_argument'
require 'oci/fleet_apps_management/models/target_credential_entity_specific_details'
require 'oci/fleet_apps_management/models/target_resource'
require 'oci/fleet_apps_management/models/target_sort_by'
require 'oci/fleet_apps_management/models/task'
require 'oci/fleet_apps_management/models/task_argument'
require 'oci/fleet_apps_management/models/task_execution_type'
require 'oci/fleet_apps_management/models/task_notification_preferences'
require 'oci/fleet_apps_management/models/task_record'
require 'oci/fleet_apps_management/models/task_record_collection'
require 'oci/fleet_apps_management/models/task_record_sort_by'
require 'oci/fleet_apps_management/models/task_record_summary'
require 'oci/fleet_apps_management/models/task_scope'
require 'oci/fleet_apps_management/models/task_variable'
require 'oci/fleet_apps_management/models/terraform_based_execution_details'
require 'oci/fleet_apps_management/models/time_based_pause_details'
require 'oci/fleet_apps_management/models/upcoming_schedule'
require 'oci/fleet_apps_management/models/update_catalog_item_details'
require 'oci/fleet_apps_management/models/update_compliance_policy_rule_details'
require 'oci/fleet_apps_management/models/update_fleet_credential_details'
require 'oci/fleet_apps_management/models/update_fleet_details'
require 'oci/fleet_apps_management/models/update_fleet_property_details'
require 'oci/fleet_apps_management/models/update_fleet_resource_details'
require 'oci/fleet_apps_management/models/update_maintenance_window_details'
require 'oci/fleet_apps_management/models/update_onboarding_details'
require 'oci/fleet_apps_management/models/update_patch_details'
require 'oci/fleet_apps_management/models/update_platform_configuration_details'
require 'oci/fleet_apps_management/models/update_property_details'
require 'oci/fleet_apps_management/models/update_provision_details'
require 'oci/fleet_apps_management/models/update_runbook_details'
require 'oci/fleet_apps_management/models/update_runbook_version_details'
require 'oci/fleet_apps_management/models/update_scheduler_definition_details'
require 'oci/fleet_apps_management/models/update_scheduler_job_details'
require 'oci/fleet_apps_management/models/update_task_record_details'
require 'oci/fleet_apps_management/models/user_action_based_pause_details'
require 'oci/fleet_apps_management/models/user_action_details'
require 'oci/fleet_apps_management/models/value_type'
require 'oci/fleet_apps_management/models/variable'
require 'oci/fleet_apps_management/models/vault_secret_credential_details'
require 'oci/fleet_apps_management/models/version'
require 'oci/fleet_apps_management/models/work_request'
require 'oci/fleet_apps_management/models/work_request_error'
require 'oci/fleet_apps_management/models/work_request_error_collection'
require 'oci/fleet_apps_management/models/work_request_log_entry'
require 'oci/fleet_apps_management/models/work_request_log_entry_collection'
require 'oci/fleet_apps_management/models/work_request_resource'
require 'oci/fleet_apps_management/models/work_request_resource_metadata_key'
require 'oci/fleet_apps_management/models/work_request_summary'
require 'oci/fleet_apps_management/models/work_request_summary_collection'
require 'oci/fleet_apps_management/models/workflow_component'
require 'oci/fleet_apps_management/models/workflow_group'
require 'oci/fleet_apps_management/models/workflow_group_component'
require 'oci/fleet_apps_management/models/workflow_task_component'

# Require generated clients
require 'oci/fleet_apps_management/fleet_apps_management_client'
require 'oci/fleet_apps_management/fleet_apps_management_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_admin_client'
require 'oci/fleet_apps_management/fleet_apps_management_admin_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_catalog_client'
require 'oci/fleet_apps_management/fleet_apps_management_catalog_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_maintenance_window_client'
require 'oci/fleet_apps_management/fleet_apps_management_maintenance_window_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_operations_client'
require 'oci/fleet_apps_management/fleet_apps_management_operations_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_provision_client'
require 'oci/fleet_apps_management/fleet_apps_management_provision_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_runbooks_client'
require 'oci/fleet_apps_management/fleet_apps_management_runbooks_client_composite_operations'
require 'oci/fleet_apps_management/fleet_apps_management_work_request_client'

# Require service utilities
require 'oci/fleet_apps_management/util'
