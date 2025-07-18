# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20190501

module OCI
  module Apigateway
    # Module containing models for requests made to, and responses received from,
    # OCI Apigateway services
    module Models
    end
  end
end

# Require models
require 'oci/apigateway/models/access_log_policy'
require 'oci/apigateway/models/additional_validation_policy'
require 'oci/apigateway/models/anonymous_route_authorization_policy'
require 'oci/apigateway/models/any_of_route_authorization_policy'
require 'oci/apigateway/models/any_of_selection_key'
require 'oci/apigateway/models/api'
require 'oci/apigateway/models/api_collection'
require 'oci/apigateway/models/api_specification'
require 'oci/apigateway/models/api_specification_logging_policies'
require 'oci/apigateway/models/api_specification_request_policies'
require 'oci/apigateway/models/api_specification_route'
require 'oci/apigateway/models/api_specification_route_backend'
require 'oci/apigateway/models/api_specification_route_request_policies'
require 'oci/apigateway/models/api_specification_route_response_policies'
require 'oci/apigateway/models/api_summary'
require 'oci/apigateway/models/api_validation_detail'
require 'oci/apigateway/models/api_validation_details'
require 'oci/apigateway/models/api_validation_result'
require 'oci/apigateway/models/api_validations'
require 'oci/apigateway/models/authentication_only_route_authorization_policy'
require 'oci/apigateway/models/authentication_policy'
require 'oci/apigateway/models/authentication_server_policy'
require 'oci/apigateway/models/body_validation_request_policy'
require 'oci/apigateway/models/ca_bundle'
require 'oci/apigateway/models/certificate'
require 'oci/apigateway/models/certificate_collection'
require 'oci/apigateway/models/certificate_summary'
require 'oci/apigateway/models/certificates_ca_bundle'
require 'oci/apigateway/models/certificates_certificate_authority'
require 'oci/apigateway/models/change_api_compartment_details'
require 'oci/apigateway/models/change_certificate_compartment_details'
require 'oci/apigateway/models/change_deployment_compartment_details'
require 'oci/apigateway/models/change_gateway_compartment_details'
require 'oci/apigateway/models/change_subscriber_compartment_details'
require 'oci/apigateway/models/change_usage_plan_compartment_details'
require 'oci/apigateway/models/client'
require 'oci/apigateway/models/client_app_details'
require 'oci/apigateway/models/client_summary'
require 'oci/apigateway/models/content_validation'
require 'oci/apigateway/models/cors_policy'
require 'oci/apigateway/models/create_api_details'
require 'oci/apigateway/models/create_certificate_details'
require 'oci/apigateway/models/create_deployment_details'
require 'oci/apigateway/models/create_gateway_details'
require 'oci/apigateway/models/create_sdk_details'
require 'oci/apigateway/models/create_subscriber_details'
require 'oci/apigateway/models/create_usage_plan_details'
require 'oci/apigateway/models/custom_authentication_policy'
require 'oci/apigateway/models/custom_client_app_details'
require 'oci/apigateway/models/deployment'
require 'oci/apigateway/models/deployment_collection'
require 'oci/apigateway/models/deployment_summary'
require 'oci/apigateway/models/discovery_uri_source_uri_details'
require 'oci/apigateway/models/dynamic_authentication_policy'
require 'oci/apigateway/models/dynamic_routing_backend'
require 'oci/apigateway/models/dynamic_routing_type_routing_backend'
require 'oci/apigateway/models/dynamic_selection_key'
require 'oci/apigateway/models/entitlement'
require 'oci/apigateway/models/entitlement_summary'
require 'oci/apigateway/models/entitlement_target'
require 'oci/apigateway/models/execution_log_policy'
require 'oci/apigateway/models/external_resp_cache'
require 'oci/apigateway/models/filter_header_policy'
require 'oci/apigateway/models/filter_header_policy_item'
require 'oci/apigateway/models/filter_query_parameter_policy'
require 'oci/apigateway/models/filter_query_parameter_policy_item'
require 'oci/apigateway/models/fixed_ttl_response_cache_store_policy'
require 'oci/apigateway/models/gateway'
require 'oci/apigateway/models/gateway_collection'
require 'oci/apigateway/models/gateway_summary'
require 'oci/apigateway/models/http_backend'
require 'oci/apigateway/models/header_field_specification'
require 'oci/apigateway/models/header_transformation_policy'
require 'oci/apigateway/models/header_validation_item'
require 'oci/apigateway/models/header_validation_request_policy'
require 'oci/apigateway/models/ip_address'
require 'oci/apigateway/models/json_web_key'
require 'oci/apigateway/models/json_web_token_claim'
require 'oci/apigateway/models/jwt_authentication_policy'
require 'oci/apigateway/models/modify_response_validation_failure_policy'
require 'oci/apigateway/models/mutual_tls_details'
require 'oci/apigateway/models/no_cache'
require 'oci/apigateway/models/no_content_validation'
require 'oci/apigateway/models/o_auth2_logout_backend'
require 'oci/apigateway/models/o_auth2_response_validation_failure_policy'
require 'oci/apigateway/models/oracle_function_backend'
require 'oci/apigateway/models/pem_encoded_public_key'
require 'oci/apigateway/models/public_key_set'
require 'oci/apigateway/models/query_parameter_transformation_policy'
require 'oci/apigateway/models/query_parameter_validation_item'
require 'oci/apigateway/models/query_parameter_validation_request_policy'
require 'oci/apigateway/models/quota'
require 'oci/apigateway/models/rate_limit'
require 'oci/apigateway/models/rate_limiting_policy'
require 'oci/apigateway/models/remote_json_web_key_set'
require 'oci/apigateway/models/rename_header_policy'
require 'oci/apigateway/models/rename_header_policy_item'
require 'oci/apigateway/models/rename_query_parameter_policy'
require 'oci/apigateway/models/rename_query_parameter_policy_item'
require 'oci/apigateway/models/request_parameter_validation'
require 'oci/apigateway/models/response_cache_details'
require 'oci/apigateway/models/response_cache_lookup_policy'
require 'oci/apigateway/models/response_cache_resp_server'
require 'oci/apigateway/models/response_cache_store_policy'
require 'oci/apigateway/models/route_authorization_policy'
require 'oci/apigateway/models/sdk'
require 'oci/apigateway/models/sdk_collection'
require 'oci/apigateway/models/sdk_language_optional_parameters'
require 'oci/apigateway/models/sdk_language_optional_parameters_allowed_value'
require 'oci/apigateway/models/sdk_language_type_collection'
require 'oci/apigateway/models/sdk_language_type_summary'
require 'oci/apigateway/models/sdk_language_types'
require 'oci/apigateway/models/sdk_summary'
require 'oci/apigateway/models/selection_source_policy'
require 'oci/apigateway/models/set_header_policy'
require 'oci/apigateway/models/set_header_policy_item'
require 'oci/apigateway/models/set_query_parameter_policy'
require 'oci/apigateway/models/set_query_parameter_policy_item'
require 'oci/apigateway/models/simple_lookup_policy'
require 'oci/apigateway/models/single_selection_source_policy'
require 'oci/apigateway/models/source_uri_details'
require 'oci/apigateway/models/static_public_key'
require 'oci/apigateway/models/static_public_key_set'
require 'oci/apigateway/models/stock_response_backend'
require 'oci/apigateway/models/subscriber'
require 'oci/apigateway/models/subscriber_collection'
require 'oci/apigateway/models/subscriber_summary'
require 'oci/apigateway/models/token_authentication_policy'
require 'oci/apigateway/models/token_authentication_remote_discovery_validation_policy'
require 'oci/apigateway/models/token_authentication_remote_jwks_validation_policy'
require 'oci/apigateway/models/token_authentication_static_keys_validation_policy'
require 'oci/apigateway/models/token_authentication_validation_policy'
require 'oci/apigateway/models/update_api_details'
require 'oci/apigateway/models/update_certificate_details'
require 'oci/apigateway/models/update_deployment_details'
require 'oci/apigateway/models/update_gateway_details'
require 'oci/apigateway/models/update_sdk_details'
require 'oci/apigateway/models/update_subscriber_details'
require 'oci/apigateway/models/update_usage_plan_details'
require 'oci/apigateway/models/usage_plan'
require 'oci/apigateway/models/usage_plan_collection'
require 'oci/apigateway/models/usage_plan_summary'
require 'oci/apigateway/models/usage_plans_policy'
require 'oci/apigateway/models/validation_block_client_app_details'
require 'oci/apigateway/models/validation_block_source_uri_details'
require 'oci/apigateway/models/validation_failure_policy'
require 'oci/apigateway/models/validation_request_policy'
require 'oci/apigateway/models/wildcard_selection_key'
require 'oci/apigateway/models/work_request'
require 'oci/apigateway/models/work_request_collection'
require 'oci/apigateway/models/work_request_error'
require 'oci/apigateway/models/work_request_error_collection'
require 'oci/apigateway/models/work_request_log'
require 'oci/apigateway/models/work_request_log_collection'
require 'oci/apigateway/models/work_request_resource'
require 'oci/apigateway/models/work_request_summary'

# Require generated clients
require 'oci/apigateway/api_gateway_client'
require 'oci/apigateway/api_gateway_client_composite_operations'
require 'oci/apigateway/deployment_client'
require 'oci/apigateway/deployment_client_composite_operations'
require 'oci/apigateway/gateway_client'
require 'oci/apigateway/gateway_client_composite_operations'
require 'oci/apigateway/subscribers_client'
require 'oci/apigateway/subscribers_client_composite_operations'
require 'oci/apigateway/usage_plans_client'
require 'oci/apigateway/usage_plans_client_composite_operations'
require 'oci/apigateway/work_requests_client'

# Require service utilities
require 'oci/apigateway/util'
