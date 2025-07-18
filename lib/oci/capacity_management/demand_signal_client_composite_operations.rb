# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20231107

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # This class provides a wrapper around {OCI::CapacityManagement::DemandSignalClient} and offers convenience methods
  # for operations that would otherwise need to be chained together. For example, instead of performing an action
  # on a resource (e.g. launching an instance, creating a load balancer) and then using a waiter to wait for the resource
  # to enter a given state, you can call a single method in this class to accomplish the same functionality
  class CapacityManagement::DemandSignalClientCompositeOperations
    # The {OCI::CapacityManagement::DemandSignalClient} used to communicate with the service_client
    #
    # @return [OCI::CapacityManagement::DemandSignalClient]
    attr_reader :service_client

    # Initializes a new DemandSignalClientCompositeOperations
    #
    # @param [OCI::CapacityManagement::DemandSignalClient] service_client The client used to communicate with the service.
    #   Defaults to a new service client created via {OCI::CapacityManagement::DemandSignalClient#initialize} with no arguments
    def initialize(service_client = OCI::CapacityManagement::DemandSignalClient.new)
      @service_client = service_client
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::CapacityManagement::DemandSignalClient#create_occm_demand_signal} and then waits for the {OCI::CapacityManagement::Models::OccmDemandSignal} acted upon
    # to enter the given state(s).
    #
    # @param [OCI::CapacityManagement::Models::CreateOccmDemandSignalDetails] create_occm_demand_signal_details The request details for creating occm demand signal.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::CapacityManagement::Models::OccmDemandSignal#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::CapacityManagement::DemandSignalClient#create_occm_demand_signal}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::CapacityManagement::Models::OccmDemandSignal}
    def create_occm_demand_signal_and_wait_for_state(create_occm_demand_signal_details, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.create_occm_demand_signal(create_occm_demand_signal_details, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_occm_demand_signal(wait_for_resource_id).wait_until(
          eval_proc: ->(response) { response.data.respond_to?(:lifecycle_state) && lowered_wait_for_states.include?(response.data.lifecycle_state.downcase) },
          max_interval_seconds: waiter_opts.key?(:max_interval_seconds) ? waiter_opts[:max_interval_seconds] : 30,
          max_wait_seconds: waiter_opts.key?(:max_wait_seconds) ? waiter_opts[:max_wait_seconds] : 1200
        )
        result_to_return = waiter_result

        return result_to_return
      rescue StandardError
        raise OCI::Errors::CompositeOperationError.new(partial_results: [operation_result])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:enable Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::CapacityManagement::DemandSignalClient#create_occm_demand_signal_item} and then waits for the {OCI::CapacityManagement::Models::OccmDemandSignalItem} acted upon
    # to enter the given state(s).
    #
    # @param [OCI::CapacityManagement::Models::CreateOccmDemandSignalItemDetails] create_occm_demand_signal_item_details The request details for creating occm demand signal item.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::CapacityManagement::Models::OccmDemandSignalItem#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::CapacityManagement::DemandSignalClient#create_occm_demand_signal_item}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::CapacityManagement::Models::OccmDemandSignalItem}
    def create_occm_demand_signal_item_and_wait_for_state(create_occm_demand_signal_item_details, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.create_occm_demand_signal_item(create_occm_demand_signal_item_details, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_occm_demand_signal_item(wait_for_resource_id).wait_until(
          eval_proc: ->(response) { response.data.respond_to?(:lifecycle_state) && lowered_wait_for_states.include?(response.data.lifecycle_state.downcase) },
          max_interval_seconds: waiter_opts.key?(:max_interval_seconds) ? waiter_opts[:max_interval_seconds] : 30,
          max_wait_seconds: waiter_opts.key?(:max_wait_seconds) ? waiter_opts[:max_wait_seconds] : 1200
        )
        result_to_return = waiter_result

        return result_to_return
      rescue StandardError
        raise OCI::Errors::CompositeOperationError.new(partial_results: [operation_result])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:enable Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::CapacityManagement::DemandSignalClient#delete_occm_demand_signal} and then waits for the {OCI::CapacityManagement::Models::OccmDemandSignal} acted upon
    # to enter the given state(s).
    #
    # @param [String] occm_demand_signal_id The OCID of the demand signal.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::CapacityManagement::Models::OccmDemandSignal#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::CapacityManagement::DemandSignalClient#delete_occm_demand_signal}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type nil
    def delete_occm_demand_signal_and_wait_for_state(occm_demand_signal_id, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      initial_get_result = @service_client.get_occm_demand_signal(occm_demand_signal_id)
      operation_result = @service_client.delete_occm_demand_signal(occm_demand_signal_id, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)

      begin
        waiter_result = initial_get_result.wait_until(
          eval_proc: ->(response) { response.data.respond_to?(:lifecycle_state) && lowered_wait_for_states.include?(response.data.lifecycle_state.downcase) },
          max_interval_seconds: waiter_opts.key?(:max_interval_seconds) ? waiter_opts[:max_interval_seconds] : 30,
          max_wait_seconds: waiter_opts.key?(:max_wait_seconds) ? waiter_opts[:max_wait_seconds] : 1200,
          succeed_on_not_found: true
        )
        result_to_return = waiter_result

        return result_to_return
      rescue StandardError
        raise OCI::Errors::CompositeOperationError.new(partial_results: [operation_result])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:enable Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::CapacityManagement::DemandSignalClient#delete_occm_demand_signal_item} and then waits for the {OCI::CapacityManagement::Models::OccmDemandSignalItem} acted upon
    # to enter the given state(s).
    #
    # @param [String] occm_demand_signal_item_id The OCID of the demand signal item.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::CapacityManagement::Models::OccmDemandSignalItem#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::CapacityManagement::DemandSignalClient#delete_occm_demand_signal_item}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type nil
    def delete_occm_demand_signal_item_and_wait_for_state(occm_demand_signal_item_id, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      initial_get_result = @service_client.get_occm_demand_signal_item(occm_demand_signal_item_id)
      operation_result = @service_client.delete_occm_demand_signal_item(occm_demand_signal_item_id, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)

      begin
        waiter_result = initial_get_result.wait_until(
          eval_proc: ->(response) { response.data.respond_to?(:lifecycle_state) && lowered_wait_for_states.include?(response.data.lifecycle_state.downcase) },
          max_interval_seconds: waiter_opts.key?(:max_interval_seconds) ? waiter_opts[:max_interval_seconds] : 30,
          max_wait_seconds: waiter_opts.key?(:max_wait_seconds) ? waiter_opts[:max_wait_seconds] : 1200,
          succeed_on_not_found: true
        )
        result_to_return = waiter_result

        return result_to_return
      rescue StandardError
        raise OCI::Errors::CompositeOperationError.new(partial_results: [operation_result])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:enable Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::CapacityManagement::DemandSignalClient#update_occm_demand_signal} and then waits for the {OCI::CapacityManagement::Models::OccmDemandSignal} acted upon
    # to enter the given state(s).
    #
    # @param [OCI::CapacityManagement::Models::UpdateOccmDemandSignalDetails] update_occm_demand_signal_details The request details for this PUT API to update the metadata for a given demand signal resource.
    #
    # @param [String] occm_demand_signal_id The OCID of the demand signal.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::CapacityManagement::Models::OccmDemandSignal#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::CapacityManagement::DemandSignalClient#update_occm_demand_signal}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::CapacityManagement::Models::OccmDemandSignal}
    def update_occm_demand_signal_and_wait_for_state(update_occm_demand_signal_details, occm_demand_signal_id, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.update_occm_demand_signal(update_occm_demand_signal_details, occm_demand_signal_id, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_occm_demand_signal(wait_for_resource_id).wait_until(
          eval_proc: ->(response) { response.data.respond_to?(:lifecycle_state) && lowered_wait_for_states.include?(response.data.lifecycle_state.downcase) },
          max_interval_seconds: waiter_opts.key?(:max_interval_seconds) ? waiter_opts[:max_interval_seconds] : 30,
          max_wait_seconds: waiter_opts.key?(:max_wait_seconds) ? waiter_opts[:max_wait_seconds] : 1200
        )
        result_to_return = waiter_result

        return result_to_return
      rescue StandardError
        raise OCI::Errors::CompositeOperationError.new(partial_results: [operation_result])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:enable Layout/EmptyLines

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::CapacityManagement::DemandSignalClient#update_occm_demand_signal_item} and then waits for the {OCI::CapacityManagement::Models::OccmDemandSignalItem} acted upon
    # to enter the given state(s).
    #
    # @param [OCI::CapacityManagement::Models::UpdateOccmDemandSignalItemDetails] update_occm_demand_signal_item_details The details about the request to update the specified demand signal item.
    #
    # @param [String] occm_demand_signal_item_id The OCID of the demand signal item.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::CapacityManagement::Models::OccmDemandSignalItem#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::CapacityManagement::DemandSignalClient#update_occm_demand_signal_item}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::CapacityManagement::Models::OccmDemandSignalItem}
    def update_occm_demand_signal_item_and_wait_for_state(update_occm_demand_signal_item_details, occm_demand_signal_item_id, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.update_occm_demand_signal_item(update_occm_demand_signal_item_details, occm_demand_signal_item_id, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_occm_demand_signal_item(wait_for_resource_id).wait_until(
          eval_proc: ->(response) { response.data.respond_to?(:lifecycle_state) && lowered_wait_for_states.include?(response.data.lifecycle_state.downcase) },
          max_interval_seconds: waiter_opts.key?(:max_interval_seconds) ? waiter_opts[:max_interval_seconds] : 30,
          max_wait_seconds: waiter_opts.key?(:max_wait_seconds) ? waiter_opts[:max_wait_seconds] : 1200
        )
        result_to_return = waiter_result

        return result_to_return
      rescue StandardError
        raise OCI::Errors::CompositeOperationError.new(partial_results: [operation_result])
      end
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:enable Layout/EmptyLines
  end
end
# rubocop:enable Lint/UnneededCopDisableDirective, Metrics/LineLength
