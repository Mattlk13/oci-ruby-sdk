# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20190101
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Retention operation details for the model.
  class DataScience::Models::RetentionOperationDetails
    ARCHIVE_STATE_ENUM = [
      ARCHIVE_STATE_PENDING = 'PENDING'.freeze,
      ARCHIVE_STATE_FAILED = 'FAILED'.freeze,
      ARCHIVE_STATE_SUCCEEDED = 'SUCCEEDED'.freeze,
      ARCHIVE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    DELETE_STATE_ENUM = [
      DELETE_STATE_PENDING = 'PENDING'.freeze,
      DELETE_STATE_FAILED = 'FAILED'.freeze,
      DELETE_STATE_SUCCEEDED = 'SUCCEEDED'.freeze,
      DELETE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The archival status of model.
    # @return [String]
    attr_reader :archive_state

    # **[Required]** The archival state details of the model.
    # @return [String]
    attr_accessor :archive_state_details

    # **[Required]** The estimated archival time of the model based on the provided retention setting.
    # @return [DateTime]
    attr_accessor :time_archival_scheduled

    # **[Required]** The deletion status of the archived model.
    # @return [String]
    attr_reader :delete_state

    # **[Required]** The deletion status details of the archived model.
    # @return [String]
    attr_accessor :delete_state_details

    # **[Required]** The estimated deletion time of the model based on the provided retention setting.
    # @return [DateTime]
    attr_accessor :time_deletion_scheduled

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'archive_state': :'archiveState',
        'archive_state_details': :'archiveStateDetails',
        'time_archival_scheduled': :'timeArchivalScheduled',
        'delete_state': :'deleteState',
        'delete_state_details': :'deleteStateDetails',
        'time_deletion_scheduled': :'timeDeletionScheduled'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'archive_state': :'String',
        'archive_state_details': :'String',
        'time_archival_scheduled': :'DateTime',
        'delete_state': :'String',
        'delete_state_details': :'String',
        'time_deletion_scheduled': :'DateTime'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :archive_state The value to assign to the {#archive_state} property
    # @option attributes [String] :archive_state_details The value to assign to the {#archive_state_details} property
    # @option attributes [DateTime] :time_archival_scheduled The value to assign to the {#time_archival_scheduled} property
    # @option attributes [String] :delete_state The value to assign to the {#delete_state} property
    # @option attributes [String] :delete_state_details The value to assign to the {#delete_state_details} property
    # @option attributes [DateTime] :time_deletion_scheduled The value to assign to the {#time_deletion_scheduled} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.archive_state = attributes[:'archiveState'] if attributes[:'archiveState']

      raise 'You cannot provide both :archiveState and :archive_state' if attributes.key?(:'archiveState') && attributes.key?(:'archive_state')

      self.archive_state = attributes[:'archive_state'] if attributes[:'archive_state']

      self.archive_state_details = attributes[:'archiveStateDetails'] if attributes[:'archiveStateDetails']

      raise 'You cannot provide both :archiveStateDetails and :archive_state_details' if attributes.key?(:'archiveStateDetails') && attributes.key?(:'archive_state_details')

      self.archive_state_details = attributes[:'archive_state_details'] if attributes[:'archive_state_details']

      self.time_archival_scheduled = attributes[:'timeArchivalScheduled'] if attributes[:'timeArchivalScheduled']

      raise 'You cannot provide both :timeArchivalScheduled and :time_archival_scheduled' if attributes.key?(:'timeArchivalScheduled') && attributes.key?(:'time_archival_scheduled')

      self.time_archival_scheduled = attributes[:'time_archival_scheduled'] if attributes[:'time_archival_scheduled']

      self.delete_state = attributes[:'deleteState'] if attributes[:'deleteState']

      raise 'You cannot provide both :deleteState and :delete_state' if attributes.key?(:'deleteState') && attributes.key?(:'delete_state')

      self.delete_state = attributes[:'delete_state'] if attributes[:'delete_state']

      self.delete_state_details = attributes[:'deleteStateDetails'] if attributes[:'deleteStateDetails']

      raise 'You cannot provide both :deleteStateDetails and :delete_state_details' if attributes.key?(:'deleteStateDetails') && attributes.key?(:'delete_state_details')

      self.delete_state_details = attributes[:'delete_state_details'] if attributes[:'delete_state_details']

      self.time_deletion_scheduled = attributes[:'timeDeletionScheduled'] if attributes[:'timeDeletionScheduled']

      raise 'You cannot provide both :timeDeletionScheduled and :time_deletion_scheduled' if attributes.key?(:'timeDeletionScheduled') && attributes.key?(:'time_deletion_scheduled')

      self.time_deletion_scheduled = attributes[:'time_deletion_scheduled'] if attributes[:'time_deletion_scheduled']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] archive_state Object to be assigned
    def archive_state=(archive_state)
      # rubocop:disable Style/ConditionalAssignment
      if archive_state && !ARCHIVE_STATE_ENUM.include?(archive_state)
        OCI.logger.debug("Unknown value for 'archive_state' [" + archive_state + "]. Mapping to 'ARCHIVE_STATE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @archive_state = ARCHIVE_STATE_UNKNOWN_ENUM_VALUE
      else
        @archive_state = archive_state
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] delete_state Object to be assigned
    def delete_state=(delete_state)
      # rubocop:disable Style/ConditionalAssignment
      if delete_state && !DELETE_STATE_ENUM.include?(delete_state)
        OCI.logger.debug("Unknown value for 'delete_state' [" + delete_state + "]. Mapping to 'DELETE_STATE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @delete_state = DELETE_STATE_UNKNOWN_ENUM_VALUE
      else
        @delete_state = delete_state
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        archive_state == other.archive_state &&
        archive_state_details == other.archive_state_details &&
        time_archival_scheduled == other.time_archival_scheduled &&
        delete_state == other.delete_state &&
        delete_state_details == other.delete_state_details &&
        time_deletion_scheduled == other.time_deletion_scheduled
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
      [archive_state, archive_state_details, time_archival_scheduled, delete_state, delete_state_details, time_deletion_scheduled].hash
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
