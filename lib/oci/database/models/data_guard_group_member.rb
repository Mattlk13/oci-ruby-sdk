# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The member of a Data Guard group. Represents either a PRIMARY or a STANDBY Data Guard instance.
  class Database::Models::DataGuardGroupMember
    ROLE_ENUM = [
      ROLE_PRIMARY = 'PRIMARY'.freeze,
      ROLE_STANDBY = 'STANDBY'.freeze,
      ROLE_DISABLED_STANDBY = 'DISABLED_STANDBY'.freeze,
      ROLE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    TRANSPORT_TYPE_ENUM = [
      TRANSPORT_TYPE_SYNC = 'SYNC'.freeze,
      TRANSPORT_TYPE_ASYNC = 'ASYNC'.freeze,
      TRANSPORT_TYPE_FASTSYNC = 'FASTSYNC'.freeze,
      TRANSPORT_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the DB system, Cloud VM cluster or VM cluster.
    # @return [String]
    attr_accessor :db_system_id

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the Database.
    # @return [String]
    attr_accessor :database_id

    # **[Required]** The role of the reporting database in this Data Guard association.
    # @return [String]
    attr_reader :role

    # The lag time between updates to the primary database and application of the redo data on the standby database,
    # as computed by the reporting database.
    #
    # Example: `1 second`
    #
    # @return [String]
    attr_accessor :apply_lag

    # The rate at which redo logs are synced between the associated databases.
    #
    # Example: `102.96 MByte/s`
    #
    # @return [String]
    attr_accessor :apply_rate

    # The rate at which redo logs are transported between the associated databases.
    #
    # Example: `1 second`
    #
    # @return [String]
    attr_accessor :transport_lag

    # The date and time when last redo transport has been done.
    # @return [String]
    attr_accessor :transport_lag_refresh

    # The redo transport type to use for this Data Guard association.  Valid values depend on the specified `protectionMode`:
    #
    # * MAXIMUM_AVAILABILITY - SYNC or FASTSYNC
    # * MAXIMUM_PERFORMANCE - ASYNC
    # * MAXIMUM_PROTECTION - SYNC
    #
    # For more information, see
    # [Redo Transport Services](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-redo-transport-services.htm#SBYDB00400)
    # in the Oracle Data Guard documentation.
    #
    # **IMPORTANT** - The only transport type currently supported by the Database service is ASYNC.
    #
    # @return [String]
    attr_reader :transport_type

    # True if active Data Guard is enabled.
    # @return [BOOLEAN]
    attr_accessor :is_active_data_guard_enabled

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'db_system_id': :'dbSystemId',
        'database_id': :'databaseId',
        'role': :'role',
        'apply_lag': :'applyLag',
        'apply_rate': :'applyRate',
        'transport_lag': :'transportLag',
        'transport_lag_refresh': :'transportLagRefresh',
        'transport_type': :'transportType',
        'is_active_data_guard_enabled': :'isActiveDataGuardEnabled'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'db_system_id': :'String',
        'database_id': :'String',
        'role': :'String',
        'apply_lag': :'String',
        'apply_rate': :'String',
        'transport_lag': :'String',
        'transport_lag_refresh': :'String',
        'transport_type': :'String',
        'is_active_data_guard_enabled': :'BOOLEAN'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :db_system_id The value to assign to the {#db_system_id} property
    # @option attributes [String] :database_id The value to assign to the {#database_id} property
    # @option attributes [String] :role The value to assign to the {#role} property
    # @option attributes [String] :apply_lag The value to assign to the {#apply_lag} property
    # @option attributes [String] :apply_rate The value to assign to the {#apply_rate} property
    # @option attributes [String] :transport_lag The value to assign to the {#transport_lag} property
    # @option attributes [String] :transport_lag_refresh The value to assign to the {#transport_lag_refresh} property
    # @option attributes [String] :transport_type The value to assign to the {#transport_type} property
    # @option attributes [BOOLEAN] :is_active_data_guard_enabled The value to assign to the {#is_active_data_guard_enabled} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.db_system_id = attributes[:'dbSystemId'] if attributes[:'dbSystemId']

      raise 'You cannot provide both :dbSystemId and :db_system_id' if attributes.key?(:'dbSystemId') && attributes.key?(:'db_system_id')

      self.db_system_id = attributes[:'db_system_id'] if attributes[:'db_system_id']

      self.database_id = attributes[:'databaseId'] if attributes[:'databaseId']

      raise 'You cannot provide both :databaseId and :database_id' if attributes.key?(:'databaseId') && attributes.key?(:'database_id')

      self.database_id = attributes[:'database_id'] if attributes[:'database_id']

      self.role = attributes[:'role'] if attributes[:'role']

      self.apply_lag = attributes[:'applyLag'] if attributes[:'applyLag']

      raise 'You cannot provide both :applyLag and :apply_lag' if attributes.key?(:'applyLag') && attributes.key?(:'apply_lag')

      self.apply_lag = attributes[:'apply_lag'] if attributes[:'apply_lag']

      self.apply_rate = attributes[:'applyRate'] if attributes[:'applyRate']

      raise 'You cannot provide both :applyRate and :apply_rate' if attributes.key?(:'applyRate') && attributes.key?(:'apply_rate')

      self.apply_rate = attributes[:'apply_rate'] if attributes[:'apply_rate']

      self.transport_lag = attributes[:'transportLag'] if attributes[:'transportLag']

      raise 'You cannot provide both :transportLag and :transport_lag' if attributes.key?(:'transportLag') && attributes.key?(:'transport_lag')

      self.transport_lag = attributes[:'transport_lag'] if attributes[:'transport_lag']

      self.transport_lag_refresh = attributes[:'transportLagRefresh'] if attributes[:'transportLagRefresh']

      raise 'You cannot provide both :transportLagRefresh and :transport_lag_refresh' if attributes.key?(:'transportLagRefresh') && attributes.key?(:'transport_lag_refresh')

      self.transport_lag_refresh = attributes[:'transport_lag_refresh'] if attributes[:'transport_lag_refresh']

      self.transport_type = attributes[:'transportType'] if attributes[:'transportType']

      raise 'You cannot provide both :transportType and :transport_type' if attributes.key?(:'transportType') && attributes.key?(:'transport_type')

      self.transport_type = attributes[:'transport_type'] if attributes[:'transport_type']

      self.is_active_data_guard_enabled = attributes[:'isActiveDataGuardEnabled'] unless attributes[:'isActiveDataGuardEnabled'].nil?

      raise 'You cannot provide both :isActiveDataGuardEnabled and :is_active_data_guard_enabled' if attributes.key?(:'isActiveDataGuardEnabled') && attributes.key?(:'is_active_data_guard_enabled')

      self.is_active_data_guard_enabled = attributes[:'is_active_data_guard_enabled'] unless attributes[:'is_active_data_guard_enabled'].nil?
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] role Object to be assigned
    def role=(role)
      # rubocop:disable Style/ConditionalAssignment
      if role && !ROLE_ENUM.include?(role)
        OCI.logger.debug("Unknown value for 'role' [" + role + "]. Mapping to 'ROLE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @role = ROLE_UNKNOWN_ENUM_VALUE
      else
        @role = role
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] transport_type Object to be assigned
    def transport_type=(transport_type)
      # rubocop:disable Style/ConditionalAssignment
      if transport_type && !TRANSPORT_TYPE_ENUM.include?(transport_type)
        OCI.logger.debug("Unknown value for 'transport_type' [" + transport_type + "]. Mapping to 'TRANSPORT_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @transport_type = TRANSPORT_TYPE_UNKNOWN_ENUM_VALUE
      else
        @transport_type = transport_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        db_system_id == other.db_system_id &&
        database_id == other.database_id &&
        role == other.role &&
        apply_lag == other.apply_lag &&
        apply_rate == other.apply_rate &&
        transport_lag == other.transport_lag &&
        transport_lag_refresh == other.transport_lag_refresh &&
        transport_type == other.transport_type &&
        is_active_data_guard_enabled == other.is_active_data_guard_enabled
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
      [db_system_id, database_id, role, apply_lag, apply_rate, transport_lag, transport_lag_refresh, transport_type, is_active_data_guard_enabled].hash
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
