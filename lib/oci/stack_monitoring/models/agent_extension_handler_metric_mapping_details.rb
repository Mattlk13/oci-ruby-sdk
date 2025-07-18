# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210330
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Specific metric mapping configurations for Agent Extension Handlers.
  class StackMonitoring::Models::AgentExtensionHandlerMetricMappingDetails
    # **[Required]** Metric name as defined by the collector.
    # @return [String]
    attr_accessor :collector_metric_name

    # Metric name to be upload to telemetry.
    # @return [String]
    attr_accessor :telemetry_metric_name

    # Is ignoring this metric.
    # @return [BOOLEAN]
    attr_accessor :is_skip_upload

    # Metric upload interval in seconds. Any metric sent by telegraf/collectd before the
    # configured interval expires will be dropped.
    #
    # @return [Integer]
    attr_accessor :metric_upload_interval_in_seconds

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'collector_metric_name': :'collectorMetricName',
        'telemetry_metric_name': :'telemetryMetricName',
        'is_skip_upload': :'isSkipUpload',
        'metric_upload_interval_in_seconds': :'metricUploadIntervalInSeconds'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'collector_metric_name': :'String',
        'telemetry_metric_name': :'String',
        'is_skip_upload': :'BOOLEAN',
        'metric_upload_interval_in_seconds': :'Integer'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :collector_metric_name The value to assign to the {#collector_metric_name} property
    # @option attributes [String] :telemetry_metric_name The value to assign to the {#telemetry_metric_name} property
    # @option attributes [BOOLEAN] :is_skip_upload The value to assign to the {#is_skip_upload} property
    # @option attributes [Integer] :metric_upload_interval_in_seconds The value to assign to the {#metric_upload_interval_in_seconds} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.collector_metric_name = attributes[:'collectorMetricName'] if attributes[:'collectorMetricName']

      raise 'You cannot provide both :collectorMetricName and :collector_metric_name' if attributes.key?(:'collectorMetricName') && attributes.key?(:'collector_metric_name')

      self.collector_metric_name = attributes[:'collector_metric_name'] if attributes[:'collector_metric_name']

      self.telemetry_metric_name = attributes[:'telemetryMetricName'] if attributes[:'telemetryMetricName']

      raise 'You cannot provide both :telemetryMetricName and :telemetry_metric_name' if attributes.key?(:'telemetryMetricName') && attributes.key?(:'telemetry_metric_name')

      self.telemetry_metric_name = attributes[:'telemetry_metric_name'] if attributes[:'telemetry_metric_name']

      self.is_skip_upload = attributes[:'isSkipUpload'] unless attributes[:'isSkipUpload'].nil?
      self.is_skip_upload = false if is_skip_upload.nil? && !attributes.key?(:'isSkipUpload') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :isSkipUpload and :is_skip_upload' if attributes.key?(:'isSkipUpload') && attributes.key?(:'is_skip_upload')

      self.is_skip_upload = attributes[:'is_skip_upload'] unless attributes[:'is_skip_upload'].nil?
      self.is_skip_upload = false if is_skip_upload.nil? && !attributes.key?(:'isSkipUpload') && !attributes.key?(:'is_skip_upload') # rubocop:disable Style/StringLiterals

      self.metric_upload_interval_in_seconds = attributes[:'metricUploadIntervalInSeconds'] if attributes[:'metricUploadIntervalInSeconds']

      raise 'You cannot provide both :metricUploadIntervalInSeconds and :metric_upload_interval_in_seconds' if attributes.key?(:'metricUploadIntervalInSeconds') && attributes.key?(:'metric_upload_interval_in_seconds')

      self.metric_upload_interval_in_seconds = attributes[:'metric_upload_interval_in_seconds'] if attributes[:'metric_upload_interval_in_seconds']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        collector_metric_name == other.collector_metric_name &&
        telemetry_metric_name == other.telemetry_metric_name &&
        is_skip_upload == other.is_skip_upload &&
        metric_upload_interval_in_seconds == other.metric_upload_interval_in_seconds
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
      [collector_metric_name, telemetry_metric_name, is_skip_upload, metric_upload_interval_in_seconds].hash
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
