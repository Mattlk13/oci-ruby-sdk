# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181201
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # A log entry related to the pre-masking health check.
  class DataSafe::Models::MaskingPolicyHealthReportLogSummary
    MESSAGE_TYPE_ENUM = [
      MESSAGE_TYPE_PASS = 'PASS'.freeze,
      MESSAGE_TYPE_WARNING = 'WARNING'.freeze,
      MESSAGE_TYPE_ERROR = 'ERROR'.freeze,
      MESSAGE_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    HEALTH_CHECK_TYPE_ENUM = [
      HEALTH_CHECK_TYPE_INVALID_OBJECT_CHECK = 'INVALID_OBJECT_CHECK'.freeze,
      HEALTH_CHECK_TYPE_PRIVILEGE_CHECK = 'PRIVILEGE_CHECK'.freeze,
      HEALTH_CHECK_TYPE_TABLESPACE_CHECK = 'TABLESPACE_CHECK'.freeze,
      HEALTH_CHECK_TYPE_DATABASE_OR_SYSTEM_TRIGGERS_CHECK = 'DATABASE_OR_SYSTEM_TRIGGERS_CHECK'.freeze,
      HEALTH_CHECK_TYPE_UNDO_TABLESPACE_CHECK = 'UNDO_TABLESPACE_CHECK'.freeze,
      HEALTH_CHECK_TYPE_STATE_STATS_CHECK = 'STATE_STATS_CHECK'.freeze,
      HEALTH_CHECK_TYPE_OLS_POLICY_CHECK = 'OLS_POLICY_CHECK'.freeze,
      HEALTH_CHECK_TYPE_VPD_POLICY_CHECK = 'VPD_POLICY_CHECK'.freeze,
      HEALTH_CHECK_TYPE_DV_ENABLE_CHECK = 'DV_ENABLE_CHECK'.freeze,
      HEALTH_CHECK_TYPE_DE_COL_SIZE_CHECK = 'DE_COL_SIZE_CHECK'.freeze,
      HEALTH_CHECK_TYPE_REDACTION_POLICY_CHECK = 'REDACTION_POLICY_CHECK'.freeze,
      HEALTH_CHECK_TYPE_ACTIVE_MASK_JOB_CHECK = 'ACTIVE_MASK_JOB_CHECK'.freeze,
      HEALTH_CHECK_TYPE_TARGET_VALIDATION_CHECK = 'TARGET_VALIDATION_CHECK'.freeze,
      HEALTH_CHECK_TYPE_DETERMINISTIC_ENCRYPTION_FORMAT_CHECK = 'DETERMINISTIC_ENCRYPTION_FORMAT_CHECK'.freeze,
      HEALTH_CHECK_TYPE_COLUMN_EXIST_CHECK = 'COLUMN_EXIST_CHECK'.freeze,
      HEALTH_CHECK_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The log entry type.
    # @return [String]
    attr_reader :message_type

    # **[Required]** The date and time the log entry was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
    #
    # @return [DateTime]
    attr_accessor :timestamp

    # **[Required]** A human-readable log entry.
    # @return [String]
    attr_accessor :message

    # A human-readable log entry to remedy any error or warnings in the masking policy.
    # @return [String]
    attr_accessor :remediation

    # **[Required]** A human-readable description for the log entry.
    # @return [String]
    attr_accessor :description

    # An enum type entry for each health check in the masking policy. Each enum describes a type of health check.
    # INVALID_OBJECT_CHECK checks if there exist any invalid objects in the masking tables.
    # PRIVILEGE_CHECK checks if the masking user has sufficient privilege to run masking.
    # TABLESPACE_CHECK checks if the user has sufficient default and TEMP tablespace.
    # DATABASE_OR_SYSTEM_TRIGGERS_CHECK checks if there exist any database/system triggers available.
    # UNDO_TABLESPACE_CHECK checks if the AUTOEXTEND feature is enabled for the undo tablespace. If it's not enabled, it further checks if the undo tablespace has any space remaining
    # STATE_STATS_CHECK checks if all the statistics of the masking table is upto date or not.
    # OLS_POLICY_CHECK , VPD_POLICY_CHECK and REDACTION_POLICY_CHECK checks if the masking tables has Oracle Label Security (OLS) or Virtual Private Database (VPD) or Redaction policies enabled.
    # DV_ENABLE_CHECK checks if database has Database Vault(DV) enabled
    # DE_COL_SIZE_CHECK checks if any masking column with DETERMINISTIC ENCRYPTION as masking format has average column size greater than 27 or not.
    # ACTIVE_MASK_JOB_CHECK checks if there is any active masking job running on the target database.
    # DETERMINISTIC_ENCRYPTION_FORMAT_CHECK checks if any masking column has deterministic encryption masking format.
    # COLUMN_EXIST_CHECK checks if the masking columns are available in the target database.
    #
    # @return [String]
    attr_reader :health_check_type

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'message_type': :'messageType',
        'timestamp': :'timestamp',
        'message': :'message',
        'remediation': :'remediation',
        'description': :'description',
        'health_check_type': :'healthCheckType'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'message_type': :'String',
        'timestamp': :'DateTime',
        'message': :'String',
        'remediation': :'String',
        'description': :'String',
        'health_check_type': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :message_type The value to assign to the {#message_type} property
    # @option attributes [DateTime] :timestamp The value to assign to the {#timestamp} property
    # @option attributes [String] :message The value to assign to the {#message} property
    # @option attributes [String] :remediation The value to assign to the {#remediation} property
    # @option attributes [String] :description The value to assign to the {#description} property
    # @option attributes [String] :health_check_type The value to assign to the {#health_check_type} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.message_type = attributes[:'messageType'] if attributes[:'messageType']

      raise 'You cannot provide both :messageType and :message_type' if attributes.key?(:'messageType') && attributes.key?(:'message_type')

      self.message_type = attributes[:'message_type'] if attributes[:'message_type']

      self.timestamp = attributes[:'timestamp'] if attributes[:'timestamp']

      self.message = attributes[:'message'] if attributes[:'message']

      self.remediation = attributes[:'remediation'] if attributes[:'remediation']

      self.description = attributes[:'description'] if attributes[:'description']

      self.health_check_type = attributes[:'healthCheckType'] if attributes[:'healthCheckType']

      raise 'You cannot provide both :healthCheckType and :health_check_type' if attributes.key?(:'healthCheckType') && attributes.key?(:'health_check_type')

      self.health_check_type = attributes[:'health_check_type'] if attributes[:'health_check_type']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] message_type Object to be assigned
    def message_type=(message_type)
      # rubocop:disable Style/ConditionalAssignment
      if message_type && !MESSAGE_TYPE_ENUM.include?(message_type)
        OCI.logger.debug("Unknown value for 'message_type' [" + message_type + "]. Mapping to 'MESSAGE_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @message_type = MESSAGE_TYPE_UNKNOWN_ENUM_VALUE
      else
        @message_type = message_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] health_check_type Object to be assigned
    def health_check_type=(health_check_type)
      # rubocop:disable Style/ConditionalAssignment
      if health_check_type && !HEALTH_CHECK_TYPE_ENUM.include?(health_check_type)
        OCI.logger.debug("Unknown value for 'health_check_type' [" + health_check_type + "]. Mapping to 'HEALTH_CHECK_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @health_check_type = HEALTH_CHECK_TYPE_UNKNOWN_ENUM_VALUE
      else
        @health_check_type = health_check_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        message_type == other.message_type &&
        timestamp == other.timestamp &&
        message == other.message &&
        remediation == other.remediation &&
        description == other.description &&
        health_check_type == other.health_check_type
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
      [message_type, timestamp, message, remediation, description, health_check_type].hash
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
