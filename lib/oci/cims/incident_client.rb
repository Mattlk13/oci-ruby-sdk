# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

require 'uri'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Use the Support Management API to manage support requests. For more information, see [Getting Help and Contacting Support](/iaas/Content/GSG/Tasks/contactingsupport.htm). **Note**: Before you can create service requests with this API, you need to have an Oracle Single Sign On (SSO) account, and you need to register your Customer Support Identifier (CSI) with My Oracle Support.
  class Cims::IncidentClient
    # Client used to make HTTP requests.
    # @return [OCI::ApiClient]
    attr_reader :api_client

    # Fully qualified endpoint URL
    # @return [String]
    attr_reader :endpoint

    # The default retry configuration to apply to all operations in this service client. This can be overridden
    # on a per-operation basis. The default retry configuration value is `nil`, which means that an operation
    # will not perform any retries
    # @return [OCI::Retry::RetryConfig]
    attr_reader :retry_config

    # The region, which will usually correspond to a value in {OCI::Regions::REGION_ENUM}.
    # @return [String]
    attr_reader :region

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Layout/EmptyLines, Metrics/PerceivedComplexity


    # Creates a new IncidentClient.
    # Notes:
    #   If a config is not specified, then the global OCI.config will be used.
    #
    #   This client is not thread-safe
    #
    #   Either a region or an endpoint must be specified.  If an endpoint is specified, it will be used instead of the
    #     region. A region may be specified in the config or via or the region parameter. If specified in both, then the
    #     region parameter will be used.
    # @param [Config] config A Config object.
    # @param [String] region A region used to determine the service endpoint. This will usually
    #   correspond to a value in {OCI::Regions::REGION_ENUM}, but may be an arbitrary string.
    # @param [String] endpoint The fully qualified endpoint URL
    # @param [OCI::BaseSigner] signer A signer implementation which can be used by this client. If this is not provided then
    #   a signer will be constructed via the provided config. One use case of this parameter is instance principals authentication,
    #   so that the instance principals signer can be provided to the client
    # @param [OCI::ApiClientProxySettings] proxy_settings If your environment requires you to use a proxy server for outgoing HTTP requests
    #   the details for the proxy can be provided in this parameter
    # @param [OCI::Retry::RetryConfig] retry_config The retry configuration for this service client. This represents the default retry configuration to
    #   apply across all operations. This can be overridden on a per-operation basis. The default retry configuration value is `nil`, which means that an operation
    #   will not perform any retries
    def initialize(config: nil, region: nil, endpoint: nil, signer: nil, proxy_settings: nil, retry_config: nil)
      # If the signer is an InstancePrincipalsSecurityTokenSigner or SecurityTokenSigner and no config was supplied (they are self-sufficient signers)
      # then create a dummy config to pass to the ApiClient constructor. If customers wish to create a client which uses instance principals
      # and has config (either populated programmatically or loaded from a file), they must construct that config themselves and then
      # pass it to this constructor.
      #
      # If there is no signer (or the signer is not an instance principals signer) and no config was supplied, this is not valid
      # so try and load the config from the default file.
      config = OCI::Config.validate_and_build_config_with_signer(config, signer)

      if signer.nil?
        signer = OCI::Signer.new(
          config.user,
          config.fingerprint,
          config.tenancy,
          config.key_file,
          pass_phrase: config.pass_phrase,
          private_key_content: config.key_content
        )
      end

      @api_client = OCI::ApiClient.new(config, signer, proxy_settings: proxy_settings)
      @retry_config = retry_config

      if endpoint
        @endpoint = endpoint + '/20181231'
      else
        region ||= config.region
        region ||= signer.region if signer.respond_to?(:region)
        self.region = region
      end
      logger.info "IncidentClient endpoint set to '#{@endpoint}'." if logger
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Layout/EmptyLines, Metrics/PerceivedComplexity

    # Set the region that will be used to determine the service endpoint.
    # This will usually correspond to a value in {OCI::Regions::REGION_ENUM},
    # but may be an arbitrary string.
    def region=(new_region)
      @region = new_region

      raise 'A region must be specified.' unless @region

      @endpoint = OCI::Regions.get_service_endpoint_for_template(@region, 'https://incidentmanagement.{region}.{secondLevelDomain}') + '/20181231'
      logger.info "IncidentClient endpoint set to '#{@endpoint} from region #{@region}'." if logger
    end

    # @return [Logger] The logger for this client. May be nil.
    def logger
      @api_client.config.logger
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # This API enables the customer to Create an Incident
    # @param [OCI::Cims::Models::CreateIncident] create_incident_details Incident information
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [String] :opc_retry_token Retry token
    # @option opts [String] :opc_request_id Unique Header for request id
    # @return [Response] A Response object with data of type {OCI::Cims::Models::Incident Incident}
    def create_incident(create_incident_details, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#create_incident.' if logger

      raise "Missing the required parameter 'create_incident_details' when calling create_incident." if create_incident_details.nil?
      raise "Missing the required parameter 'ocid' when calling create_incident." if ocid.nil?

      path = '/v2/incidents'
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:ocid] = ocid
      header_params[:'opc-retry-token'] = opts[:opc_retry_token] if opts[:opc_retry_token]
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      # rubocop:enable Style/NegatedIf
      header_params[:'opc-retry-token'] ||= OCI::Retry.generate_opc_retry_token

      post_body = @api_client.object_to_http_body(create_incident_details)

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#create_incident') do
        @api_client.call_api(
          :POST,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'OCI::Cims::Models::Incident'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # This API fetches the details of a requested Incident
    # @param [String] incident_key Unique ID that identifies an incident
    # @param [String] csi Customer Support Identifier of the support account
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [String] :opc_request_id Unique Header for request id
    # @return [Response] A Response object with data of type {OCI::Cims::Models::Incident Incident}
    def get_incident(incident_key, csi, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#get_incident.' if logger

      raise "Missing the required parameter 'incident_key' when calling get_incident." if incident_key.nil?
      raise "Missing the required parameter 'csi' when calling get_incident." if csi.nil?
      raise "Missing the required parameter 'ocid' when calling get_incident." if ocid.nil?
      raise "Parameter value for 'incident_key' must not be blank" if OCI::Internal::Util.blank_string?(incident_key)

      path = '/v2/incidents/{incidentKey}'.sub('{incidentKey}', incident_key.to_s)
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:csi] = csi
      header_params[:ocid] = ocid
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      # rubocop:enable Style/NegatedIf

      post_body = nil

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#get_incident') do
        @api_client.call_api(
          :GET,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'OCI::Cims::Models::Incident'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # GetStatus of the Service
    # @param [String] source Source is a downstream system. Eg: JIRA or MOS or any other source in future.
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [String] :opc_request_id Unique Header for request id
    # @return [Response] A Response object with data of type {OCI::Cims::Models::Status Status}
    def get_status(source, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#get_status.' if logger

      raise "Missing the required parameter 'source' when calling get_status." if source.nil?
      raise "Missing the required parameter 'ocid' when calling get_status." if ocid.nil?
      raise "Parameter value for 'source' must not be blank" if OCI::Internal::Util.blank_string?(source)

      path = '/v2/incidents/status/{source}'.sub('{source}', source.to_s)
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:ocid] = ocid
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      # rubocop:enable Style/NegatedIf

      post_body = nil

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#get_status') do
        @api_client.call_api(
          :GET,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'OCI::Cims::Models::Status'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # This API returns the list of all possible product that OCI supports, while creating an incident
    # @param [String] problem_type Problem Type of Taxonomy - tech/limit
    # @param [String] compartment_id Tenancy Ocid
    # @param [String] csi Customer Support Identifier of the support account
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [String] :opc_request_id Unique Header for request id
    # @option opts [Integer] :limit Limit query for number of returned results (default to 50)
    # @option opts [String] :page Pagination for Incident list (default to 1)
    # @option opts [String] :sort_by The key to sort the returned items by (default to dateUpdated)
    # @option opts [String] :sort_order The order in which to sort the results (default to ASC)
    # @option opts [String] :name Name of Incident Type. eg: Limit Increase (default to limit)
    # @return [Response] A Response object with data of type Array<{OCI::Cims::Models::IncidentResourceType IncidentResourceType}>
    def list_incident_resource_types(problem_type, compartment_id, csi, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#list_incident_resource_types.' if logger

      raise "Missing the required parameter 'problem_type' when calling list_incident_resource_types." if problem_type.nil?
      raise "Missing the required parameter 'compartment_id' when calling list_incident_resource_types." if compartment_id.nil?
      raise "Missing the required parameter 'csi' when calling list_incident_resource_types." if csi.nil?
      raise "Missing the required parameter 'ocid' when calling list_incident_resource_types." if ocid.nil?

      if opts[:sort_by] && !OCI::Cims::Models::SORT_BY_ENUM.include?(opts[:sort_by])
        raise 'Invalid value for "sort_by", must be one of the values in OCI::Cims::Models::SORT_BY_ENUM.'
      end

      if opts[:sort_order] && !OCI::Cims::Models::SORT_ORDER_ENUM.include?(opts[:sort_order])
        raise 'Invalid value for "sort_order", must be one of the values in OCI::Cims::Models::SORT_ORDER_ENUM.'
      end

      path = '/v2/incidents/incidentResourceTypes'
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}
      query_params[:problemType] = problem_type
      query_params[:compartmentId] = compartment_id
      query_params[:limit] = opts[:limit] if opts[:limit]
      query_params[:page] = opts[:page] if opts[:page]
      query_params[:sortBy] = opts[:sort_by] if opts[:sort_by]
      query_params[:sortOrder] = opts[:sort_order] if opts[:sort_order]
      query_params[:name] = opts[:name] if opts[:name]

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:csi] = csi
      header_params[:ocid] = ocid
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      # rubocop:enable Style/NegatedIf

      post_body = nil

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#list_incident_resource_types') do
        @api_client.call_api(
          :GET,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'Array<OCI::Cims::Models::IncidentResourceType>'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # This API returns the list of incidents raised by the tenant
    # @param [String] csi Customer Support Identifier of the support account
    # @param [String] compartment_id Tenancy Ocid
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [Integer] :limit Limit query for number of returned results (default to 50)
    # @option opts [String] :sort_by The key to sort the returned items by (default to dateUpdated)
    # @option opts [String] :sort_order The order in which to sort the results (default to ASC)
    # @option opts [String] :lifecycle_state The order in which to sort the results (default to ACTIVE)
    # @option opts [String] :page Pagination for Incident list (default to 1)
    # @option opts [String] :opc_request_id Unique Header for request id
    # @return [Response] A Response object with data of type Array<{OCI::Cims::Models::IncidentSummary IncidentSummary}>
    def list_incidents(csi, compartment_id, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#list_incidents.' if logger

      raise "Missing the required parameter 'csi' when calling list_incidents." if csi.nil?
      raise "Missing the required parameter 'compartment_id' when calling list_incidents." if compartment_id.nil?
      raise "Missing the required parameter 'ocid' when calling list_incidents." if ocid.nil?

      if opts[:sort_by] && !OCI::Cims::Models::SORT_BY_ENUM.include?(opts[:sort_by])
        raise 'Invalid value for "sort_by", must be one of the values in OCI::Cims::Models::SORT_BY_ENUM.'
      end

      if opts[:sort_order] && !OCI::Cims::Models::SORT_ORDER_ENUM.include?(opts[:sort_order])
        raise 'Invalid value for "sort_order", must be one of the values in OCI::Cims::Models::SORT_ORDER_ENUM.'
      end

      if opts[:lifecycle_state] && !OCI::Cims::Models::LIFECYCLE_STATE_ENUM.include?(opts[:lifecycle_state])
        raise 'Invalid value for "lifecycle_state", must be one of the values in OCI::Cims::Models::LIFECYCLE_STATE_ENUM.'
      end

      path = '/v2/incidents'
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}
      query_params[:compartmentId] = compartment_id
      query_params[:limit] = opts[:limit] if opts[:limit]
      query_params[:sortBy] = opts[:sort_by] if opts[:sort_by]
      query_params[:sortOrder] = opts[:sort_order] if opts[:sort_order]
      query_params[:lifecycleState] = opts[:lifecycle_state] if opts[:lifecycle_state]
      query_params[:page] = opts[:page] if opts[:page]

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:csi] = csi
      header_params[:ocid] = ocid
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      # rubocop:enable Style/NegatedIf

      post_body = nil

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#list_incidents') do
        @api_client.call_api(
          :GET,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'Array<OCI::Cims::Models::IncidentSummary>'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # This API updates an existing incident
    # @param [String] incident_key Unique ID that identifies an incident
    # @param [String] csi Customer Support Identifier of the support account
    # @param [OCI::Cims::Models::UpdateIncident] update_incident_details Details of Resource to be updated
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [String] :opc_retry_token Retry token
    # @option opts [String] :opc_request_id Unique Header for request id
    # @option opts [String] :if_match if-match check
    # @return [Response] A Response object with data of type {OCI::Cims::Models::Incident Incident}
    def update_incident(incident_key, csi, update_incident_details, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#update_incident.' if logger

      raise "Missing the required parameter 'incident_key' when calling update_incident." if incident_key.nil?
      raise "Missing the required parameter 'csi' when calling update_incident." if csi.nil?
      raise "Missing the required parameter 'update_incident_details' when calling update_incident." if update_incident_details.nil?
      raise "Missing the required parameter 'ocid' when calling update_incident." if ocid.nil?
      raise "Parameter value for 'incident_key' must not be blank" if OCI::Internal::Util.blank_string?(incident_key)

      path = '/v2/incidents/{incidentKey}'.sub('{incidentKey}', incident_key.to_s)
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:csi] = csi
      header_params[:ocid] = ocid
      header_params[:'opc-retry-token'] = opts[:opc_retry_token] if opts[:opc_retry_token]
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      header_params[:'if-match'] = opts[:if_match] if opts[:if_match]
      # rubocop:enable Style/NegatedIf
      header_params[:'opc-retry-token'] ||= OCI::Retry.generate_opc_retry_token

      post_body = @api_client.object_to_http_body(update_incident_details)

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#update_incident') do
        @api_client.call_api(
          :PUT,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'OCI::Cims::Models::Incident'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines


    # ValidateUser
    # @param [String] csi Customer support identifier of the support account
    # @param [String] ocid User OCID for IDCS users that have a shadow in OCI
    # @param [Hash] opts the optional parameters
    # @option opts [OCI::Retry::RetryConfig] :retry_config The retry configuration to apply to this operation. If no key is provided then the service-level
    #   retry configuration defined by {#retry_config} will be used. If an explicit `nil` value is provided then the operation will not retry
    # @option opts [String] :opc_retry_token Retry-token header
    # @option opts [String] :opc_request_id Unique request id
    # @option opts [String] :problem_type Problem Type of Taxonomy - tech/limit
    # @return [Response] A Response object with data of type {OCI::Cims::Models::ValidationResponse ValidationResponse}
    def validate_user(csi, ocid, opts = {})
      logger.debug 'Calling operation IncidentClient#validate_user.' if logger

      raise "Missing the required parameter 'csi' when calling validate_user." if csi.nil?
      raise "Missing the required parameter 'ocid' when calling validate_user." if ocid.nil?

      path = '/v2/incidents/user/validate'
      operation_signing_strategy = :standard

      # rubocop:disable Style/NegatedIf
      # Query Params
      query_params = {}
      query_params[:problemType] = opts[:problem_type] if opts[:problem_type]

      # Header Params
      header_params = {}
      header_params[:accept] = 'application/json'
      header_params[:'content-type'] = 'application/json'
      header_params[:csi] = csi
      header_params[:ocid] = ocid
      header_params[:'opc-retry-token'] = opts[:opc_retry_token] if opts[:opc_retry_token]
      header_params[:'opc-request-id'] = opts[:opc_request_id] if opts[:opc_request_id]
      # rubocop:enable Style/NegatedIf
      header_params[:'opc-retry-token'] ||= OCI::Retry.generate_opc_retry_token

      post_body = nil

      # rubocop:disable Metrics/BlockLength
      OCI::Retry.make_retrying_call(applicable_retry_config(opts), call_name: 'IncidentClient#validate_user') do
        @api_client.call_api(
          :GET,
          path,
          endpoint,
          header_params: header_params,
          query_params: query_params,
          operation_signing_strategy: operation_signing_strategy,
          body: post_body,
          return_type: 'OCI::Cims::Models::ValidationResponse'
        )
      end
      # rubocop:enable Metrics/BlockLength
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Style/IfUnlessModifier, Metrics/ParameterLists
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines

    private

    def applicable_retry_config(opts = {})
      return @retry_config unless opts.key?(:retry_config)

      opts[:retry_config]
    end
  end
end
# rubocop:enable Lint/UnneededCopDisableDirective, Metrics/LineLength
