# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220901
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Data related to the sysadmin event.
  class OsManagementHub::Models::SysadminEventData
    RESOLUTION_STATUS_ENUM = [
      RESOLUTION_STATUS_SUCCEEDED = 'SUCCEEDED'.freeze,
      RESOLUTION_STATUS_FAILED = 'FAILED'.freeze,
      RESOLUTION_STATUS_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The commands executed by the agent that caused the error.
    # @return [String]
    attr_accessor :error_cause

    # **[Required]** The output log of the error.
    # @return [String]
    attr_accessor :error_log

    # **[Required]** The actions used to attempt fixing the error.
    # @return [Array<String>]
    attr_accessor :attempted_resolutions

    # **[Required]** Indicates if the event succeeded.
    # @return [String]
    attr_reader :resolution_status

    # **[Required]** The log output after the resolutions.
    # @return [String]
    attr_accessor :resolution_log

    # @return [OCI::OsManagementHub::Models::WorkRequestEventDataAdditionalDetails]
    attr_accessor :additional_details

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'error_cause': :'errorCause',
        'error_log': :'errorLog',
        'attempted_resolutions': :'attemptedResolutions',
        'resolution_status': :'resolutionStatus',
        'resolution_log': :'resolutionLog',
        'additional_details': :'additionalDetails'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'error_cause': :'String',
        'error_log': :'String',
        'attempted_resolutions': :'Array<String>',
        'resolution_status': :'String',
        'resolution_log': :'String',
        'additional_details': :'OCI::OsManagementHub::Models::WorkRequestEventDataAdditionalDetails'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :error_cause The value to assign to the {#error_cause} property
    # @option attributes [String] :error_log The value to assign to the {#error_log} property
    # @option attributes [Array<String>] :attempted_resolutions The value to assign to the {#attempted_resolutions} property
    # @option attributes [String] :resolution_status The value to assign to the {#resolution_status} property
    # @option attributes [String] :resolution_log The value to assign to the {#resolution_log} property
    # @option attributes [OCI::OsManagementHub::Models::WorkRequestEventDataAdditionalDetails] :additional_details The value to assign to the {#additional_details} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.error_cause = attributes[:'errorCause'] if attributes[:'errorCause']

      raise 'You cannot provide both :errorCause and :error_cause' if attributes.key?(:'errorCause') && attributes.key?(:'error_cause')

      self.error_cause = attributes[:'error_cause'] if attributes[:'error_cause']

      self.error_log = attributes[:'errorLog'] if attributes[:'errorLog']

      raise 'You cannot provide both :errorLog and :error_log' if attributes.key?(:'errorLog') && attributes.key?(:'error_log')

      self.error_log = attributes[:'error_log'] if attributes[:'error_log']

      self.attempted_resolutions = attributes[:'attemptedResolutions'] if attributes[:'attemptedResolutions']

      raise 'You cannot provide both :attemptedResolutions and :attempted_resolutions' if attributes.key?(:'attemptedResolutions') && attributes.key?(:'attempted_resolutions')

      self.attempted_resolutions = attributes[:'attempted_resolutions'] if attributes[:'attempted_resolutions']

      self.resolution_status = attributes[:'resolutionStatus'] if attributes[:'resolutionStatus']

      raise 'You cannot provide both :resolutionStatus and :resolution_status' if attributes.key?(:'resolutionStatus') && attributes.key?(:'resolution_status')

      self.resolution_status = attributes[:'resolution_status'] if attributes[:'resolution_status']

      self.resolution_log = attributes[:'resolutionLog'] if attributes[:'resolutionLog']

      raise 'You cannot provide both :resolutionLog and :resolution_log' if attributes.key?(:'resolutionLog') && attributes.key?(:'resolution_log')

      self.resolution_log = attributes[:'resolution_log'] if attributes[:'resolution_log']

      self.additional_details = attributes[:'additionalDetails'] if attributes[:'additionalDetails']

      raise 'You cannot provide both :additionalDetails and :additional_details' if attributes.key?(:'additionalDetails') && attributes.key?(:'additional_details')

      self.additional_details = attributes[:'additional_details'] if attributes[:'additional_details']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] resolution_status Object to be assigned
    def resolution_status=(resolution_status)
      # rubocop:disable Style/ConditionalAssignment
      if resolution_status && !RESOLUTION_STATUS_ENUM.include?(resolution_status)
        OCI.logger.debug("Unknown value for 'resolution_status' [" + resolution_status + "]. Mapping to 'RESOLUTION_STATUS_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @resolution_status = RESOLUTION_STATUS_UNKNOWN_ENUM_VALUE
      else
        @resolution_status = resolution_status
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        error_cause == other.error_cause &&
        error_log == other.error_log &&
        attempted_resolutions == other.attempted_resolutions &&
        resolution_status == other.resolution_status &&
        resolution_log == other.resolution_log &&
        additional_details == other.additional_details
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
      [error_cause, error_log, attempted_resolutions, resolution_status, resolution_log, additional_details].hash
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
