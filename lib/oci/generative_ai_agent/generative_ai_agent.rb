# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20240531

module OCI
  module GenerativeAiAgent
    # Module containing models for requests made to, and responses received from,
    # OCI GenerativeAiAgent services
    module Models
    end
  end
end

# Require models
require 'oci/generative_ai_agent/models/action_type'
require 'oci/generative_ai_agent/models/agent'
require 'oci/generative_ai_agent/models/agent_collection'
require 'oci/generative_ai_agent/models/agent_endpoint'
require 'oci/generative_ai_agent/models/agent_endpoint_collection'
require 'oci/generative_ai_agent/models/agent_endpoint_summary'
require 'oci/generative_ai_agent/models/agent_summary'
require 'oci/generative_ai_agent/models/api_schema_inline_input_location'
require 'oci/generative_ai_agent/models/api_schema_input_location'
require 'oci/generative_ai_agent/models/api_schema_object_storage_input_location'
require 'oci/generative_ai_agent/models/basic_auth_secret'
require 'oci/generative_ai_agent/models/change_agent_compartment_details'
require 'oci/generative_ai_agent/models/change_agent_endpoint_compartment_details'
require 'oci/generative_ai_agent/models/change_knowledge_base_compartment_details'
require 'oci/generative_ai_agent/models/content_moderation_config'
require 'oci/generative_ai_agent/models/content_moderation_guardrail_config'
require 'oci/generative_ai_agent/models/create_agent_details'
require 'oci/generative_ai_agent/models/create_agent_endpoint_details'
require 'oci/generative_ai_agent/models/create_data_ingestion_job_details'
require 'oci/generative_ai_agent/models/create_data_source_details'
require 'oci/generative_ai_agent/models/create_knowledge_base_details'
require 'oci/generative_ai_agent/models/create_tool_details'
require 'oci/generative_ai_agent/models/data_ingestion_job'
require 'oci/generative_ai_agent/models/data_ingestion_job_collection'
require 'oci/generative_ai_agent/models/data_ingestion_job_statistics'
require 'oci/generative_ai_agent/models/data_ingestion_job_summary'
require 'oci/generative_ai_agent/models/data_source'
require 'oci/generative_ai_agent/models/data_source_collection'
require 'oci/generative_ai_agent/models/data_source_config'
require 'oci/generative_ai_agent/models/data_source_summary'
require 'oci/generative_ai_agent/models/database_connection'
require 'oci/generative_ai_agent/models/database_function'
require 'oci/generative_ai_agent/models/database_tool_connection'
require 'oci/generative_ai_agent/models/default_index_config'
require 'oci/generative_ai_agent/models/function'
require 'oci/generative_ai_agent/models/function_calling_tool_config'
require 'oci/generative_ai_agent/models/guardrail_config'
require 'oci/generative_ai_agent/models/guardrail_mode'
require 'oci/generative_ai_agent/models/http_endpoint_auth_config'
require 'oci/generative_ai_agent/models/http_endpoint_delegated_bearer_auth_config'
require 'oci/generative_ai_agent/models/http_endpoint_idcs_auth_config'
require 'oci/generative_ai_agent/models/http_endpoint_no_auth_config'
require 'oci/generative_ai_agent/models/http_endpoint_oci_resource_principal_auth_config'
require 'oci/generative_ai_agent/models/http_endpoint_tool_config'
require 'oci/generative_ai_agent/models/human_input_config'
require 'oci/generative_ai_agent/models/idcs_secret'
require 'oci/generative_ai_agent/models/index'
require 'oci/generative_ai_agent/models/index_config'
require 'oci/generative_ai_agent/models/index_schema'
require 'oci/generative_ai_agent/models/inline_input_location'
require 'oci/generative_ai_agent/models/input_location'
require 'oci/generative_ai_agent/models/knowledge_base'
require 'oci/generative_ai_agent/models/knowledge_base_collection'
require 'oci/generative_ai_agent/models/knowledge_base_config'
require 'oci/generative_ai_agent/models/knowledge_base_statistics'
require 'oci/generative_ai_agent/models/knowledge_base_summary'
require 'oci/generative_ai_agent/models/llm_config'
require 'oci/generative_ai_agent/models/llm_customization'
require 'oci/generative_ai_agent/models/object_storage_input_location'
require 'oci/generative_ai_agent/models/object_storage_prefix'
require 'oci/generative_ai_agent/models/object_storage_prefix_output_location'
require 'oci/generative_ai_agent/models/oci_database_config'
require 'oci/generative_ai_agent/models/oci_object_storage_data_source_config'
require 'oci/generative_ai_agent/models/oci_open_search_index_config'
require 'oci/generative_ai_agent/models/operation_status'
require 'oci/generative_ai_agent/models/operation_type'
require 'oci/generative_ai_agent/models/output_config'
require 'oci/generative_ai_agent/models/output_location'
require 'oci/generative_ai_agent/models/personally_identifiable_information_guardrail_config'
require 'oci/generative_ai_agent/models/prompt_injection_guardrail_config'
require 'oci/generative_ai_agent/models/rag_tool_config'
require 'oci/generative_ai_agent/models/secret_detail'
require 'oci/generative_ai_agent/models/session_config'
require 'oci/generative_ai_agent/models/sort_order'
require 'oci/generative_ai_agent/models/sql_tool_config'
require 'oci/generative_ai_agent/models/tool'
require 'oci/generative_ai_agent/models/tool_collection'
require 'oci/generative_ai_agent/models/tool_config'
require 'oci/generative_ai_agent/models/tool_summary'
require 'oci/generative_ai_agent/models/update_agent_details'
require 'oci/generative_ai_agent/models/update_agent_endpoint_details'
require 'oci/generative_ai_agent/models/update_data_source_details'
require 'oci/generative_ai_agent/models/update_knowledge_base_details'
require 'oci/generative_ai_agent/models/update_tool_details'
require 'oci/generative_ai_agent/models/work_request'
require 'oci/generative_ai_agent/models/work_request_error'
require 'oci/generative_ai_agent/models/work_request_error_collection'
require 'oci/generative_ai_agent/models/work_request_log_entry'
require 'oci/generative_ai_agent/models/work_request_log_entry_collection'
require 'oci/generative_ai_agent/models/work_request_resource'
require 'oci/generative_ai_agent/models/work_request_resource_metadata_key'
require 'oci/generative_ai_agent/models/work_request_summary'
require 'oci/generative_ai_agent/models/work_request_summary_collection'

# Require generated clients
require 'oci/generative_ai_agent/generative_ai_agent_client'
require 'oci/generative_ai_agent/generative_ai_agent_client_composite_operations'

# Require service utilities
require 'oci/generative_ai_agent/util'
