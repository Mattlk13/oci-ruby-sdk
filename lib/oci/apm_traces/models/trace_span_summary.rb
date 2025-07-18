# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200630
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Summary of the information pertaining to the spans in the trace window that is being queried.
  #
  class ApmTraces::Models::TraceSpanSummary
    # **[Required]** Unique identifier (traceId) for the trace that represents the span set.  Note that this field is
    # defined as traceKey in the API and it maps to the traceId in the trace data in Application Performance
    # Monitoring.
    #
    # @return [String]
    attr_accessor :key

    # Root span name associated with the trace. This is the flow start operation name.
    # Null is displayed if the root span is not yet completed.
    #
    # @return [String]
    attr_accessor :root_span_operation_name

    # **[Required]** Start time of the earliest span in the span collection.
    #
    # @return [DateTime]
    attr_accessor :time_earliest_span_started

    # **[Required]** End time of the span that most recently ended in the span collection.
    #
    # @return [DateTime]
    attr_accessor :time_latest_span_ended

    # **[Required]** The number of spans that have been processed by the system for the trace.  Note that there
    # could be additional spans that have not been processed or reported yet if the trace is still
    # in progress.
    #
    # @return [Integer]
    attr_accessor :span_count

    # **[Required]** The number of spans with errors that have been processed by the system for the trace.
    # Note that the number of spans with errors will be less than or equal to the total number of spans in the trace.
    #
    # @return [Integer]
    attr_accessor :error_span_count

    # Service associated with the trace.
    #
    # @return [String]
    attr_accessor :root_span_service_name

    # Start time of the root span for the span collection.
    #
    # @return [DateTime]
    attr_accessor :time_root_span_started

    # End time of the root span for the span collection.
    #
    # @return [DateTime]
    attr_accessor :time_root_span_ended

    # Time taken for the root span operation to complete in milliseconds.
    #
    # @return [Integer]
    attr_accessor :root_span_duration_in_ms

    # **[Required]** Time between the start of the earliest span and the end of the most recent span in milliseconds.
    #
    # @return [Integer]
    attr_accessor :trace_duration_in_ms

    # **[Required]** Boolean flag that indicates whether the trace has an error.
    #
    # @return [BOOLEAN]
    attr_accessor :is_fault

    # **[Required]** The status of the trace.
    # The trace statuses are defined as follows:
    # complete - a root span has been recorded, but there is no information on the errors.
    # success - a complete root span is recorded there is a successful error type and error code - HTTP 200.
    # incomplete - the root span has not yet been received.
    # error - the root span returned with an error. There may or may not be an associated error code or error type.
    #
    # @return [String]
    attr_accessor :trace_status

    # **[Required]** Error type of the trace.
    #
    # @return [String]
    attr_accessor :trace_error_type

    # **[Required]** Error code of the trace.
    #
    # @return [String]
    attr_accessor :trace_error_code

    # A summary of the spans by service.
    #
    # @return [Array<OCI::ApmTraces::Models::TraceServiceSummary>]
    attr_accessor :service_summaries

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'key': :'key',
        'root_span_operation_name': :'rootSpanOperationName',
        'time_earliest_span_started': :'timeEarliestSpanStarted',
        'time_latest_span_ended': :'timeLatestSpanEnded',
        'span_count': :'spanCount',
        'error_span_count': :'errorSpanCount',
        'root_span_service_name': :'rootSpanServiceName',
        'time_root_span_started': :'timeRootSpanStarted',
        'time_root_span_ended': :'timeRootSpanEnded',
        'root_span_duration_in_ms': :'rootSpanDurationInMs',
        'trace_duration_in_ms': :'traceDurationInMs',
        'is_fault': :'isFault',
        'trace_status': :'traceStatus',
        'trace_error_type': :'traceErrorType',
        'trace_error_code': :'traceErrorCode',
        'service_summaries': :'serviceSummaries'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'key': :'String',
        'root_span_operation_name': :'String',
        'time_earliest_span_started': :'DateTime',
        'time_latest_span_ended': :'DateTime',
        'span_count': :'Integer',
        'error_span_count': :'Integer',
        'root_span_service_name': :'String',
        'time_root_span_started': :'DateTime',
        'time_root_span_ended': :'DateTime',
        'root_span_duration_in_ms': :'Integer',
        'trace_duration_in_ms': :'Integer',
        'is_fault': :'BOOLEAN',
        'trace_status': :'String',
        'trace_error_type': :'String',
        'trace_error_code': :'String',
        'service_summaries': :'Array<OCI::ApmTraces::Models::TraceServiceSummary>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :key The value to assign to the {#key} property
    # @option attributes [String] :root_span_operation_name The value to assign to the {#root_span_operation_name} property
    # @option attributes [DateTime] :time_earliest_span_started The value to assign to the {#time_earliest_span_started} property
    # @option attributes [DateTime] :time_latest_span_ended The value to assign to the {#time_latest_span_ended} property
    # @option attributes [Integer] :span_count The value to assign to the {#span_count} property
    # @option attributes [Integer] :error_span_count The value to assign to the {#error_span_count} property
    # @option attributes [String] :root_span_service_name The value to assign to the {#root_span_service_name} property
    # @option attributes [DateTime] :time_root_span_started The value to assign to the {#time_root_span_started} property
    # @option attributes [DateTime] :time_root_span_ended The value to assign to the {#time_root_span_ended} property
    # @option attributes [Integer] :root_span_duration_in_ms The value to assign to the {#root_span_duration_in_ms} property
    # @option attributes [Integer] :trace_duration_in_ms The value to assign to the {#trace_duration_in_ms} property
    # @option attributes [BOOLEAN] :is_fault The value to assign to the {#is_fault} property
    # @option attributes [String] :trace_status The value to assign to the {#trace_status} property
    # @option attributes [String] :trace_error_type The value to assign to the {#trace_error_type} property
    # @option attributes [String] :trace_error_code The value to assign to the {#trace_error_code} property
    # @option attributes [Array<OCI::ApmTraces::Models::TraceServiceSummary>] :service_summaries The value to assign to the {#service_summaries} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.key = attributes[:'key'] if attributes[:'key']

      self.root_span_operation_name = attributes[:'rootSpanOperationName'] if attributes[:'rootSpanOperationName']

      raise 'You cannot provide both :rootSpanOperationName and :root_span_operation_name' if attributes.key?(:'rootSpanOperationName') && attributes.key?(:'root_span_operation_name')

      self.root_span_operation_name = attributes[:'root_span_operation_name'] if attributes[:'root_span_operation_name']

      self.time_earliest_span_started = attributes[:'timeEarliestSpanStarted'] if attributes[:'timeEarliestSpanStarted']

      raise 'You cannot provide both :timeEarliestSpanStarted and :time_earliest_span_started' if attributes.key?(:'timeEarliestSpanStarted') && attributes.key?(:'time_earliest_span_started')

      self.time_earliest_span_started = attributes[:'time_earliest_span_started'] if attributes[:'time_earliest_span_started']

      self.time_latest_span_ended = attributes[:'timeLatestSpanEnded'] if attributes[:'timeLatestSpanEnded']

      raise 'You cannot provide both :timeLatestSpanEnded and :time_latest_span_ended' if attributes.key?(:'timeLatestSpanEnded') && attributes.key?(:'time_latest_span_ended')

      self.time_latest_span_ended = attributes[:'time_latest_span_ended'] if attributes[:'time_latest_span_ended']

      self.span_count = attributes[:'spanCount'] if attributes[:'spanCount']

      raise 'You cannot provide both :spanCount and :span_count' if attributes.key?(:'spanCount') && attributes.key?(:'span_count')

      self.span_count = attributes[:'span_count'] if attributes[:'span_count']

      self.error_span_count = attributes[:'errorSpanCount'] if attributes[:'errorSpanCount']

      raise 'You cannot provide both :errorSpanCount and :error_span_count' if attributes.key?(:'errorSpanCount') && attributes.key?(:'error_span_count')

      self.error_span_count = attributes[:'error_span_count'] if attributes[:'error_span_count']

      self.root_span_service_name = attributes[:'rootSpanServiceName'] if attributes[:'rootSpanServiceName']

      raise 'You cannot provide both :rootSpanServiceName and :root_span_service_name' if attributes.key?(:'rootSpanServiceName') && attributes.key?(:'root_span_service_name')

      self.root_span_service_name = attributes[:'root_span_service_name'] if attributes[:'root_span_service_name']

      self.time_root_span_started = attributes[:'timeRootSpanStarted'] if attributes[:'timeRootSpanStarted']

      raise 'You cannot provide both :timeRootSpanStarted and :time_root_span_started' if attributes.key?(:'timeRootSpanStarted') && attributes.key?(:'time_root_span_started')

      self.time_root_span_started = attributes[:'time_root_span_started'] if attributes[:'time_root_span_started']

      self.time_root_span_ended = attributes[:'timeRootSpanEnded'] if attributes[:'timeRootSpanEnded']

      raise 'You cannot provide both :timeRootSpanEnded and :time_root_span_ended' if attributes.key?(:'timeRootSpanEnded') && attributes.key?(:'time_root_span_ended')

      self.time_root_span_ended = attributes[:'time_root_span_ended'] if attributes[:'time_root_span_ended']

      self.root_span_duration_in_ms = attributes[:'rootSpanDurationInMs'] if attributes[:'rootSpanDurationInMs']

      raise 'You cannot provide both :rootSpanDurationInMs and :root_span_duration_in_ms' if attributes.key?(:'rootSpanDurationInMs') && attributes.key?(:'root_span_duration_in_ms')

      self.root_span_duration_in_ms = attributes[:'root_span_duration_in_ms'] if attributes[:'root_span_duration_in_ms']

      self.trace_duration_in_ms = attributes[:'traceDurationInMs'] if attributes[:'traceDurationInMs']

      raise 'You cannot provide both :traceDurationInMs and :trace_duration_in_ms' if attributes.key?(:'traceDurationInMs') && attributes.key?(:'trace_duration_in_ms')

      self.trace_duration_in_ms = attributes[:'trace_duration_in_ms'] if attributes[:'trace_duration_in_ms']

      self.is_fault = attributes[:'isFault'] unless attributes[:'isFault'].nil?

      raise 'You cannot provide both :isFault and :is_fault' if attributes.key?(:'isFault') && attributes.key?(:'is_fault')

      self.is_fault = attributes[:'is_fault'] unless attributes[:'is_fault'].nil?

      self.trace_status = attributes[:'traceStatus'] if attributes[:'traceStatus']

      raise 'You cannot provide both :traceStatus and :trace_status' if attributes.key?(:'traceStatus') && attributes.key?(:'trace_status')

      self.trace_status = attributes[:'trace_status'] if attributes[:'trace_status']

      self.trace_error_type = attributes[:'traceErrorType'] if attributes[:'traceErrorType']

      raise 'You cannot provide both :traceErrorType and :trace_error_type' if attributes.key?(:'traceErrorType') && attributes.key?(:'trace_error_type')

      self.trace_error_type = attributes[:'trace_error_type'] if attributes[:'trace_error_type']

      self.trace_error_code = attributes[:'traceErrorCode'] if attributes[:'traceErrorCode']

      raise 'You cannot provide both :traceErrorCode and :trace_error_code' if attributes.key?(:'traceErrorCode') && attributes.key?(:'trace_error_code')

      self.trace_error_code = attributes[:'trace_error_code'] if attributes[:'trace_error_code']

      self.service_summaries = attributes[:'serviceSummaries'] if attributes[:'serviceSummaries']

      raise 'You cannot provide both :serviceSummaries and :service_summaries' if attributes.key?(:'serviceSummaries') && attributes.key?(:'service_summaries')

      self.service_summaries = attributes[:'service_summaries'] if attributes[:'service_summaries']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        key == other.key &&
        root_span_operation_name == other.root_span_operation_name &&
        time_earliest_span_started == other.time_earliest_span_started &&
        time_latest_span_ended == other.time_latest_span_ended &&
        span_count == other.span_count &&
        error_span_count == other.error_span_count &&
        root_span_service_name == other.root_span_service_name &&
        time_root_span_started == other.time_root_span_started &&
        time_root_span_ended == other.time_root_span_ended &&
        root_span_duration_in_ms == other.root_span_duration_in_ms &&
        trace_duration_in_ms == other.trace_duration_in_ms &&
        is_fault == other.is_fault &&
        trace_status == other.trace_status &&
        trace_error_type == other.trace_error_type &&
        trace_error_code == other.trace_error_code &&
        service_summaries == other.service_summaries
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines

    # @see the `==` method
    # @param [Object] other the other object to be compared
    def eql?(other)
      self == other
    end

    # rubocop:disable Metrics/AbcSize, Layout/EmptyLines


    # Calculates hash code according to all attributes.
    # @return [Fixnum] Hash code
    def hash
      [key, root_span_operation_name, time_earliest_span_started, time_latest_span_ended, span_count, error_span_count, root_span_service_name, time_root_span_started, time_root_span_ended, root_span_duration_in_ms, trace_duration_in_ms, is_fault, trace_status, trace_error_type, trace_error_code, service_summaries].hash
    end
    # rubocop:enable Metrics/AbcSize, Layout/EmptyLines

    # rubocop:disable Metrics/AbcSize, Layout/EmptyLines


    # Builds the object from hash
    # @param [Hash] attributes Model attributes in the form of hash
    # @return [Object] Returns the model itself
    def build_from_hash(attributes)
      return nil unless attributes.is_a?(Hash)

      self.class.swagger_types.each_pair do |key, type|
        if type =~ /^Array<(.*)>/i
          # check to ensure the input is an array given that the the attribute
          # is documented as an array but the input is not
          if attributes[self.class.attribute_map[key]].is_a?(Array)
            public_method("#{key}=").call(
              attributes[self.class.attribute_map[key]]
                .map { |v| OCI::Internal::Util.convert_to_type(Regexp.last_match(1), v) }
            )
          end
        elsif !attributes[self.class.attribute_map[key]].nil?
          public_method("#{key}=").call(
            OCI::Internal::Util.convert_to_type(type, attributes[self.class.attribute_map[key]])
          )
        end
        # or else data not found in attributes(hash), not an issue as the data can be optional
      end

      self
    end
    # rubocop:enable Metrics/AbcSize, Layout/EmptyLines

    # Returns the string representation of the object
    # @return [String] String presentation of the object
    def to_s
      to_hash.to_s
    end

    # Returns the object in the form of hash
    # @return [Hash] Returns the object in the form of hash
    def to_hash
      hash = {}
      self.class.attribute_map.each_pair do |attr, param|
        value = public_method(attr).call
        next if value.nil? && !instance_variable_defined?("@#{attr}")

        hash[param] = _to_hash(value)
      end
      hash
    end

    private

    # Outputs non-array value in the form of hash
    # For object, use to_hash. Otherwise, just return the value
    # @param [Object] value Any valid value
    # @return [Hash] Returns the value in the form of hash
    def _to_hash(value)
      if value.is_a?(Array)
        value.compact.map { |v| _to_hash(v) }
      elsif value.is_a?(Hash)
        {}.tap do |hash|
          value.each { |k, v| hash[k] = _to_hash(v) }
        end
      elsif value.respond_to? :to_hash
        value.to_hash
      else
        value
      end
    end
  end
end
# rubocop:enable Lint/UnneededCopDisableDirective, Metrics/LineLength
