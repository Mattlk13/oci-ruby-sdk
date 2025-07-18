# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20250228
require 'date'
require_relative 'action_group_details'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # A string variable that holds a value
  class FleetAppsManagement::Models::FleetBasedActionGroupDetails < FleetAppsManagement::Models::ActionGroupDetails
    # **[Required]** ID of the fleet
    # @return [String]
    attr_accessor :fleet_id

    # sequence of the Action Group
    # @return [Integer]
    attr_accessor :sequence

    # **[Required]** ID of the runbook
    # @return [String]
    attr_accessor :runbook_id

    # **[Required]** Name of the runbook version
    # @return [String]
    attr_accessor :runbook_version_name

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'displayName',
        'kind': :'kind',
        'product': :'product',
        'lifecycle_operation': :'lifecycleOperation',
        'activity_id': :'activityId',
        'status': :'status',
        'time_started': :'timeStarted',
        'time_ended': :'timeEnded',
        'fleet_id': :'fleetId',
        'sequence': :'sequence',
        'runbook_id': :'runbookId',
        'runbook_version_name': :'runbookVersionName'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'String',
        'kind': :'String',
        'product': :'String',
        'lifecycle_operation': :'String',
        'activity_id': :'String',
        'status': :'String',
        'time_started': :'DateTime',
        'time_ended': :'DateTime',
        'fleet_id': :'String',
        'sequence': :'Integer',
        'runbook_id': :'String',
        'runbook_version_name': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :display_name The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#display_name #display_name} proprety
    # @option attributes [String] :product The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#product #product} proprety
    # @option attributes [String] :lifecycle_operation The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#lifecycle_operation #lifecycle_operation} proprety
    # @option attributes [String] :activity_id The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#activity_id #activity_id} proprety
    # @option attributes [String] :status The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#status #status} proprety
    # @option attributes [DateTime] :time_started The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#time_started #time_started} proprety
    # @option attributes [DateTime] :time_ended The value to assign to the {OCI::FleetAppsManagement::Models::ActionGroupDetails#time_ended #time_ended} proprety
    # @option attributes [String] :fleet_id The value to assign to the {#fleet_id} property
    # @option attributes [Integer] :sequence The value to assign to the {#sequence} property
    # @option attributes [String] :runbook_id The value to assign to the {#runbook_id} property
    # @option attributes [String] :runbook_version_name The value to assign to the {#runbook_version_name} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      attributes['kind'] = 'FLEET_USING_RUNBOOK'

      super(attributes)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.fleet_id = attributes[:'fleetId'] if attributes[:'fleetId']

      raise 'You cannot provide both :fleetId and :fleet_id' if attributes.key?(:'fleetId') && attributes.key?(:'fleet_id')

      self.fleet_id = attributes[:'fleet_id'] if attributes[:'fleet_id']

      self.sequence = attributes[:'sequence'] if attributes[:'sequence']

      self.runbook_id = attributes[:'runbookId'] if attributes[:'runbookId']

      raise 'You cannot provide both :runbookId and :runbook_id' if attributes.key?(:'runbookId') && attributes.key?(:'runbook_id')

      self.runbook_id = attributes[:'runbook_id'] if attributes[:'runbook_id']

      self.runbook_version_name = attributes[:'runbookVersionName'] if attributes[:'runbookVersionName']

      raise 'You cannot provide both :runbookVersionName and :runbook_version_name' if attributes.key?(:'runbookVersionName') && attributes.key?(:'runbook_version_name')

      self.runbook_version_name = attributes[:'runbook_version_name'] if attributes[:'runbook_version_name']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        display_name == other.display_name &&
        kind == other.kind &&
        product == other.product &&
        lifecycle_operation == other.lifecycle_operation &&
        activity_id == other.activity_id &&
        status == other.status &&
        time_started == other.time_started &&
        time_ended == other.time_ended &&
        fleet_id == other.fleet_id &&
        sequence == other.sequence &&
        runbook_id == other.runbook_id &&
        runbook_version_name == other.runbook_version_name
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
      [display_name, kind, product, lifecycle_operation, activity_id, status, time_started, time_ended, fleet_id, sequence, runbook_id, runbook_version_name].hash
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
