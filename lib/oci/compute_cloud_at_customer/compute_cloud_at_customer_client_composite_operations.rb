# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20221208

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # This class provides a wrapper around {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient} and offers convenience methods
  # for operations that would otherwise need to be chained together. For example, instead of performing an action
  # on a resource (e.g. launching an instance, creating a load balancer) and then using a waiter to wait for the resource
  # to enter a given state, you can call a single method in this class to accomplish the same functionality
  class ComputeCloudAtCustomer::ComputeCloudAtCustomerClientCompositeOperations
    # The {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient} used to communicate with the service_client
    #
    # @return [OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient]
    attr_reader :service_client

    # Initializes a new ComputeCloudAtCustomerClientCompositeOperations
    #
    # @param [OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient] service_client The client used to communicate with the service.
    #   Defaults to a new service client created via {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#initialize} with no arguments
    def initialize(service_client = OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient.new)
      @service_client = service_client
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/ParameterLists, Metrics/PerceivedComplexity
    # rubocop:disable Layout/EmptyLines


    # Calls {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#create_ccc_infrastructure} and then waits for the {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure} acted upon
    # to enter the given state(s).
    #
    # @param [OCI::ComputeCloudAtCustomer::Models::CreateCccInfrastructureDetails] create_ccc_infrastructure_details Details for the new CccInfrastructure.
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#create_ccc_infrastructure}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure}
    def create_ccc_infrastructure_and_wait_for_state(create_ccc_infrastructure_details, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.create_ccc_infrastructure(create_ccc_infrastructure_details, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_ccc_infrastructure(wait_for_resource_id).wait_until(
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


    # Calls {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#create_ccc_upgrade_schedule} and then waits for the {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule} acted upon
    # to enter the given state(s).
    #
    # @param [OCI::ComputeCloudAtCustomer::Models::CreateCccUpgradeScheduleDetails] create_ccc_upgrade_schedule_details Details for the new CCC Upgrade Schedule.
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#create_ccc_upgrade_schedule}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule}
    def create_ccc_upgrade_schedule_and_wait_for_state(create_ccc_upgrade_schedule_details, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.create_ccc_upgrade_schedule(create_ccc_upgrade_schedule_details, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_ccc_upgrade_schedule(wait_for_resource_id).wait_until(
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


    # Calls {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#delete_ccc_infrastructure} and then waits for the {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure} acted upon
    # to enter the given state(s).
    #
    # @param [String] ccc_infrastructure_id An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a
    #   Compute Cloud@Customer Infrastructure.
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#delete_ccc_infrastructure}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type nil
    def delete_ccc_infrastructure_and_wait_for_state(ccc_infrastructure_id, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      initial_get_result = @service_client.get_ccc_infrastructure(ccc_infrastructure_id)
      operation_result = @service_client.delete_ccc_infrastructure(ccc_infrastructure_id, base_operation_opts)

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


    # Calls {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#delete_ccc_upgrade_schedule} and then waits for the {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule} acted upon
    # to enter the given state(s).
    #
    # @param [String] ccc_upgrade_schedule_id Compute Cloud@Customer upgrade schedule
    #   [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    #
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#delete_ccc_upgrade_schedule}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type nil
    def delete_ccc_upgrade_schedule_and_wait_for_state(ccc_upgrade_schedule_id, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      initial_get_result = @service_client.get_ccc_upgrade_schedule(ccc_upgrade_schedule_id)
      operation_result = @service_client.delete_ccc_upgrade_schedule(ccc_upgrade_schedule_id, base_operation_opts)

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


    # Calls {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#update_ccc_infrastructure} and then waits for the {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure} acted upon
    # to enter the given state(s).
    #
    # @param [String] ccc_infrastructure_id An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a
    #   Compute Cloud@Customer Infrastructure.
    #
    # @param [OCI::ComputeCloudAtCustomer::Models::UpdateCccInfrastructureDetails] update_ccc_infrastructure_details The information to be updated.
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#update_ccc_infrastructure}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::ComputeCloudAtCustomer::Models::CccInfrastructure}
    def update_ccc_infrastructure_and_wait_for_state(ccc_infrastructure_id, update_ccc_infrastructure_details, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.update_ccc_infrastructure(ccc_infrastructure_id, update_ccc_infrastructure_details, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_ccc_infrastructure(wait_for_resource_id).wait_until(
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


    # Calls {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#update_ccc_upgrade_schedule} and then waits for the {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule} acted upon
    # to enter the given state(s).
    #
    # @param [String] ccc_upgrade_schedule_id Compute Cloud@Customer upgrade schedule
    #   [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    #
    # @param [OCI::ComputeCloudAtCustomer::Models::UpdateCccUpgradeScheduleDetails] update_ccc_upgrade_schedule_details The information to be updated in the Compute Cloud@Customer upgrade schedule.
    # @param [Array<String>] wait_for_states An array of states to wait on. These should be valid values for {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule#lifecycle_state}
    # @param [Hash] base_operation_opts Any optional arguments accepted by {OCI::ComputeCloudAtCustomer::ComputeCloudAtCustomerClient#update_ccc_upgrade_schedule}
    # @param [Hash] waiter_opts Optional arguments for the waiter. Keys should be symbols, and the following keys are supported:
    #   * max_interval_seconds: The maximum interval between queries, in seconds.
    #   * max_wait_seconds The maximum time to wait, in seconds
    #
    # @return [OCI::Response] A {OCI::Response} object with data of type {OCI::ComputeCloudAtCustomer::Models::CccUpgradeSchedule}
    def update_ccc_upgrade_schedule_and_wait_for_state(ccc_upgrade_schedule_id, update_ccc_upgrade_schedule_details, wait_for_states = [], base_operation_opts = {}, waiter_opts = {})
      operation_result = @service_client.update_ccc_upgrade_schedule(ccc_upgrade_schedule_id, update_ccc_upgrade_schedule_details, base_operation_opts)

      return operation_result if wait_for_states.empty?

      lowered_wait_for_states = wait_for_states.map(&:downcase)
      wait_for_resource_id = operation_result.data.id

      begin
        waiter_result = @service_client.get_ccc_upgrade_schedule(wait_for_resource_id).wait_until(
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
