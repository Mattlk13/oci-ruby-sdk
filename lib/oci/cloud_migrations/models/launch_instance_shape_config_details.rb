# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220919
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The shape configuration requested for the instance.
  #
  # If the parameter is provided, the instance is created with the resources that you specify. If some
  # properties are missing or the entire parameter is not provided, the instance is created
  # with the default configuration values for the `shape` that you specify.
  #
  # Each shape only supports certain configurable values. If the values that you provide are not valid for the
  # specified `shape`, an error is returned.
  #
  class CloudMigrations::Models::LaunchInstanceShapeConfigDetails
    BASELINE_OCPU_UTILIZATION_ENUM = [
      BASELINE_OCPU_UTILIZATION_BASELINE_1_8 = 'BASELINE_1_8'.freeze,
      BASELINE_OCPU_UTILIZATION_BASELINE_1_2 = 'BASELINE_1_2'.freeze,
      BASELINE_OCPU_UTILIZATION_BASELINE_1_1 = 'BASELINE_1_1'.freeze,
      BASELINE_OCPU_UTILIZATION_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # The total number of OCPUs available to the instance.
    #
    # @return [Float]
    attr_accessor :ocpus

    # The total amount of memory in gigabytes that is available to the instance.
    #
    # @return [Float]
    attr_accessor :memory_in_gbs

    # The baseline OCPU utilization for a subcore burstable VM instance. Leave this attribute blank for a
    # non-burstable instance, or explicitly specify non-burstable with `BASELINE_1_1`.
    #
    # The following values are supported:
    # - `BASELINE_1_8` - baseline usage is 1/8 of an OCPU.
    # - `BASELINE_1_2` - baseline usage is 1/2 of an OCPU.
    # - `BASELINE_1_1` - baseline usage is an entire OCPU. This represents a non-burstable instance.
    #
    # @return [String]
    attr_reader :baseline_ocpu_utilization

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'ocpus': :'ocpus',
        'memory_in_gbs': :'memoryInGBs',
        'baseline_ocpu_utilization': :'baselineOcpuUtilization'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'ocpus': :'Float',
        'memory_in_gbs': :'Float',
        'baseline_ocpu_utilization': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [Float] :ocpus The value to assign to the {#ocpus} property
    # @option attributes [Float] :memory_in_gbs The value to assign to the {#memory_in_gbs} property
    # @option attributes [String] :baseline_ocpu_utilization The value to assign to the {#baseline_ocpu_utilization} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.ocpus = attributes[:'ocpus'] if attributes[:'ocpus']

      self.memory_in_gbs = attributes[:'memoryInGBs'] if attributes[:'memoryInGBs']

      raise 'You cannot provide both :memoryInGBs and :memory_in_gbs' if attributes.key?(:'memoryInGBs') && attributes.key?(:'memory_in_gbs')

      self.memory_in_gbs = attributes[:'memory_in_gbs'] if attributes[:'memory_in_gbs']

      self.baseline_ocpu_utilization = attributes[:'baselineOcpuUtilization'] if attributes[:'baselineOcpuUtilization']

      raise 'You cannot provide both :baselineOcpuUtilization and :baseline_ocpu_utilization' if attributes.key?(:'baselineOcpuUtilization') && attributes.key?(:'baseline_ocpu_utilization')

      self.baseline_ocpu_utilization = attributes[:'baseline_ocpu_utilization'] if attributes[:'baseline_ocpu_utilization']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] baseline_ocpu_utilization Object to be assigned
    def baseline_ocpu_utilization=(baseline_ocpu_utilization)
      # rubocop:disable Style/ConditionalAssignment
      if baseline_ocpu_utilization && !BASELINE_OCPU_UTILIZATION_ENUM.include?(baseline_ocpu_utilization)
        OCI.logger.debug("Unknown value for 'baseline_ocpu_utilization' [" + baseline_ocpu_utilization + "]. Mapping to 'BASELINE_OCPU_UTILIZATION_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @baseline_ocpu_utilization = BASELINE_OCPU_UTILIZATION_UNKNOWN_ENUM_VALUE
      else
        @baseline_ocpu_utilization = baseline_ocpu_utilization
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        ocpus == other.ocpus &&
        memory_in_gbs == other.memory_in_gbs &&
        baseline_ocpu_utilization == other.baseline_ocpu_utilization
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
      [ocpus, memory_in_gbs, baseline_ocpu_utilization].hash
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
