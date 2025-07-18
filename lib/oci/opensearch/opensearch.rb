# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20180828

module OCI
  module Opensearch
    # Module containing models for requests made to, and responses received from,
    # OCI Opensearch services
    module Models
    end
  end
end

# Require models
require 'oci/opensearch/models/action_type'
require 'oci/opensearch/models/backup_event_details'
require 'oci/opensearch/models/backup_opensearch_cluster_details'
require 'oci/opensearch/models/backup_policy'
require 'oci/opensearch/models/backup_state'
require 'oci/opensearch/models/benchmark_details'
require 'oci/opensearch/models/ccc_mode'
require 'oci/opensearch/models/change_opensearch_cluster_backup_compartment_details'
require 'oci/opensearch/models/change_opensearch_cluster_compartment_details'
require 'oci/opensearch/models/configure_outbound_cluster_details'
require 'oci/opensearch/models/create_maintenance_details'
require 'oci/opensearch/models/create_opensearch_cluster_details'
require 'oci/opensearch/models/create_opensearch_cluster_pipeline_details'
require 'oci/opensearch/models/customer_logging_details'
require 'oci/opensearch/models/data_node_host_type'
require 'oci/opensearch/models/delete_block_volumes_for_namespace_details'
require 'oci/opensearch/models/export_opensearch_cluster_backup_details'
require 'oci/opensearch/models/force_patch_cluster_details'
require 'oci/opensearch/models/force_patch_pipeline_details'
require 'oci/opensearch/models/get_manifest_response'
require 'oci/opensearch/models/maintenance_details'
require 'oci/opensearch/models/maintenance_notification_details'
require 'oci/opensearch/models/maintenance_notification_failure'
require 'oci/opensearch/models/maintenance_notification_response'
require 'oci/opensearch/models/maintenance_notification_type'
require 'oci/opensearch/models/maintenance_state'
require 'oci/opensearch/models/master_node_host_type'
require 'oci/opensearch/models/opensearch_cluster'
require 'oci/opensearch/models/opensearch_cluster_backup'
require 'oci/opensearch/models/opensearch_cluster_backup_collection'
require 'oci/opensearch/models/opensearch_cluster_backup_summary'
require 'oci/opensearch/models/opensearch_cluster_collection'
require 'oci/opensearch/models/opensearch_cluster_internal_details'
require 'oci/opensearch/models/opensearch_cluster_pipeline'
require 'oci/opensearch/models/opensearch_cluster_pipeline_collection'
require 'oci/opensearch/models/opensearch_cluster_pipeline_summary'
require 'oci/opensearch/models/opensearch_cluster_summary'
require 'oci/opensearch/models/opensearch_pipeline_reverse_connection_endpoint'
require 'oci/opensearch/models/opensearch_versions_collection'
require 'oci/opensearch/models/opensearch_versions_summary'
require 'oci/opensearch/models/operation_status'
require 'oci/opensearch/models/operation_type'
require 'oci/opensearch/models/outbound_cluster_config'
require 'oci/opensearch/models/outbound_cluster_summary'
require 'oci/opensearch/models/reclaim_cluster_details'
require 'oci/opensearch/models/resize_opensearch_cluster_horizontal_details'
require 'oci/opensearch/models/resize_opensearch_cluster_vertical_details'
require 'oci/opensearch/models/restore_opensearch_cluster_backup_details'
require 'oci/opensearch/models/restore_opensearch_cluster_details'
require 'oci/opensearch/models/reverse_connection_endpoint'
require 'oci/opensearch/models/search_node_host_type'
require 'oci/opensearch/models/security_mode'
require 'oci/opensearch/models/security_saml_config'
require 'oci/opensearch/models/shapes_details'
require 'oci/opensearch/models/sort_order'
require 'oci/opensearch/models/update_checkin_details'
require 'oci/opensearch/models/update_cluster_hardened_image_details'
require 'oci/opensearch/models/update_cluster_specs_details'
require 'oci/opensearch/models/update_cluster_status_details'
require 'oci/opensearch/models/update_maintenance_details'
require 'oci/opensearch/models/update_opensearch_cluster_backup_details'
require 'oci/opensearch/models/update_opensearch_cluster_details'
require 'oci/opensearch/models/update_opensearch_cluster_pipeline_details'
require 'oci/opensearch/models/update_pipeline_status_details'
require 'oci/opensearch/models/upgrade_open_search_cluster_details'
require 'oci/opensearch/models/upgrade_type'
require 'oci/opensearch/models/work_request'
require 'oci/opensearch/models/work_request_collection'
require 'oci/opensearch/models/work_request_error'
require 'oci/opensearch/models/work_request_error_collection'
require 'oci/opensearch/models/work_request_log_entry'
require 'oci/opensearch/models/work_request_log_entry_collection'
require 'oci/opensearch/models/work_request_resource'

# Require generated clients
require 'oci/opensearch/opensearch_cluster_client'
require 'oci/opensearch/opensearch_cluster_client_composite_operations'
require 'oci/opensearch/opensearch_cluster_backup_client'
require 'oci/opensearch/opensearch_cluster_backup_client_composite_operations'
require 'oci/opensearch/opensearch_cluster_pipeline_client'
require 'oci/opensearch/opensearch_cluster_pipeline_client_composite_operations'

# Require service utilities
require 'oci/opensearch/util'
