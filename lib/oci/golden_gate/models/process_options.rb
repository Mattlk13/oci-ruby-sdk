# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200407
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Required pipeline options to configure the replication process (Extract or Replicat).
  #
  class GoldenGate::Models::ProcessOptions
    SHOULD_RESTART_ON_FAILURE_ENUM = [
      SHOULD_RESTART_ON_FAILURE_ENABLED = 'ENABLED'.freeze,
      SHOULD_RESTART_ON_FAILURE_DISABLED = 'DISABLED'.freeze,
      SHOULD_RESTART_ON_FAILURE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    START_USING_DEFAULT_MAPPING_ENUM = [
      START_USING_DEFAULT_MAPPING_ENABLED = 'ENABLED'.freeze,
      START_USING_DEFAULT_MAPPING_DISABLED = 'DISABLED'.freeze,
      START_USING_DEFAULT_MAPPING_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # This attribute is required.
    # @return [OCI::GoldenGate::Models::InitialDataLoad]
    attr_accessor :initial_data_load

    # This attribute is required.
    # @return [OCI::GoldenGate::Models::ReplicateSchemaChange]
    attr_accessor :replicate_schema_change

    # **[Required]** If ENABLED, then the replication process restarts itself upon failure. This option applies when creating or updating a pipeline.
    #
    # @return [String]
    attr_reader :should_restart_on_failure

    # If ENABLED, then the pipeline is started as part of pipeline creation. It uses default mapping. This option applies when creating or updating a pipeline.
    #
    # @return [String]
    attr_reader :start_using_default_mapping

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'initial_data_load': :'initialDataLoad',
        'replicate_schema_change': :'replicateSchemaChange',
        'should_restart_on_failure': :'shouldRestartOnFailure',
        'start_using_default_mapping': :'startUsingDefaultMapping'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'initial_data_load': :'OCI::GoldenGate::Models::InitialDataLoad',
        'replicate_schema_change': :'OCI::GoldenGate::Models::ReplicateSchemaChange',
        'should_restart_on_failure': :'String',
        'start_using_default_mapping': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [OCI::GoldenGate::Models::InitialDataLoad] :initial_data_load The value to assign to the {#initial_data_load} property
    # @option attributes [OCI::GoldenGate::Models::ReplicateSchemaChange] :replicate_schema_change The value to assign to the {#replicate_schema_change} property
    # @option attributes [String] :should_restart_on_failure The value to assign to the {#should_restart_on_failure} property
    # @option attributes [String] :start_using_default_mapping The value to assign to the {#start_using_default_mapping} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.initial_data_load = attributes[:'initialDataLoad'] if attributes[:'initialDataLoad']

      raise 'You cannot provide both :initialDataLoad and :initial_data_load' if attributes.key?(:'initialDataLoad') && attributes.key?(:'initial_data_load')

      self.initial_data_load = attributes[:'initial_data_load'] if attributes[:'initial_data_load']

      self.replicate_schema_change = attributes[:'replicateSchemaChange'] if attributes[:'replicateSchemaChange']

      raise 'You cannot provide both :replicateSchemaChange and :replicate_schema_change' if attributes.key?(:'replicateSchemaChange') && attributes.key?(:'replicate_schema_change')

      self.replicate_schema_change = attributes[:'replicate_schema_change'] if attributes[:'replicate_schema_change']

      self.should_restart_on_failure = attributes[:'shouldRestartOnFailure'] if attributes[:'shouldRestartOnFailure']
      self.should_restart_on_failure = "ENABLED" if should_restart_on_failure.nil? && !attributes.key?(:'shouldRestartOnFailure') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :shouldRestartOnFailure and :should_restart_on_failure' if attributes.key?(:'shouldRestartOnFailure') && attributes.key?(:'should_restart_on_failure')

      self.should_restart_on_failure = attributes[:'should_restart_on_failure'] if attributes[:'should_restart_on_failure']
      self.should_restart_on_failure = "ENABLED" if should_restart_on_failure.nil? && !attributes.key?(:'shouldRestartOnFailure') && !attributes.key?(:'should_restart_on_failure') # rubocop:disable Style/StringLiterals

      self.start_using_default_mapping = attributes[:'startUsingDefaultMapping'] if attributes[:'startUsingDefaultMapping']
      self.start_using_default_mapping = "DISABLED" if start_using_default_mapping.nil? && !attributes.key?(:'startUsingDefaultMapping') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :startUsingDefaultMapping and :start_using_default_mapping' if attributes.key?(:'startUsingDefaultMapping') && attributes.key?(:'start_using_default_mapping')

      self.start_using_default_mapping = attributes[:'start_using_default_mapping'] if attributes[:'start_using_default_mapping']
      self.start_using_default_mapping = "DISABLED" if start_using_default_mapping.nil? && !attributes.key?(:'startUsingDefaultMapping') && !attributes.key?(:'start_using_default_mapping') # rubocop:disable Style/StringLiterals
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] should_restart_on_failure Object to be assigned
    def should_restart_on_failure=(should_restart_on_failure)
      # rubocop:disable Style/ConditionalAssignment
      if should_restart_on_failure && !SHOULD_RESTART_ON_FAILURE_ENUM.include?(should_restart_on_failure)
        OCI.logger.debug("Unknown value for 'should_restart_on_failure' [" + should_restart_on_failure + "]. Mapping to 'SHOULD_RESTART_ON_FAILURE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @should_restart_on_failure = SHOULD_RESTART_ON_FAILURE_UNKNOWN_ENUM_VALUE
      else
        @should_restart_on_failure = should_restart_on_failure
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] start_using_default_mapping Object to be assigned
    def start_using_default_mapping=(start_using_default_mapping)
      # rubocop:disable Style/ConditionalAssignment
      if start_using_default_mapping && !START_USING_DEFAULT_MAPPING_ENUM.include?(start_using_default_mapping)
        OCI.logger.debug("Unknown value for 'start_using_default_mapping' [" + start_using_default_mapping + "]. Mapping to 'START_USING_DEFAULT_MAPPING_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @start_using_default_mapping = START_USING_DEFAULT_MAPPING_UNKNOWN_ENUM_VALUE
      else
        @start_using_default_mapping = start_using_default_mapping
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        initial_data_load == other.initial_data_load &&
        replicate_schema_change == other.replicate_schema_change &&
        should_restart_on_failure == other.should_restart_on_failure &&
        start_using_default_mapping == other.start_using_default_mapping
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
      [initial_data_load, replicate_schema_change, should_restart_on_failure, start_using_default_mapping].hash
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
