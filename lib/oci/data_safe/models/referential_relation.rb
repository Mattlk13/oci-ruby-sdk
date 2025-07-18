# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20181201
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # A referential relation is a resource corresponding to database columns.
  # It's a subresource of sensitive data model resource and is always associated with a sensitive data model.
  #
  class DataSafe::Models::ReferentialRelation
    LIFECYCLE_STATE_ENUM = [
      LIFECYCLE_STATE_CREATING = 'CREATING'.freeze,
      LIFECYCLE_STATE_ACTIVE = 'ACTIVE'.freeze,
      LIFECYCLE_STATE_UPDATING = 'UPDATING'.freeze,
      LIFECYCLE_STATE_DELETING = 'DELETING'.freeze,
      LIFECYCLE_STATE_FAILED = 'FAILED'.freeze,
      LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    RELATION_TYPE_ENUM = [
      RELATION_TYPE_NONE = 'NONE'.freeze,
      RELATION_TYPE_APP_DEFINED = 'APP_DEFINED'.freeze,
      RELATION_TYPE_DB_DEFINED = 'DB_DEFINED'.freeze,
      RELATION_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The unique key that identifies the referential relation. It's numeric and unique within a sensitive data model.
    # @return [String]
    attr_accessor :key

    # **[Required]** The current state of the referential relation.
    # @return [String]
    attr_reader :lifecycle_state

    # **[Required]** The OCID of the sensitive data model that contains the sensitive column.
    # @return [String]
    attr_accessor :sensitive_data_model_id

    # **[Required]** The type of referential relationship the sensitive column has with its parent. NONE indicates that the
    # sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database
    # dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
    #
    # @return [String]
    attr_reader :relation_type

    # This attribute is required.
    # @return [OCI::DataSafe::Models::ColumnsInfo]
    attr_accessor :parent

    # This attribute is required.
    # @return [OCI::DataSafe::Models::ColumnsInfo]
    attr_accessor :child

    # Determines if the columns present in the referential relation is present in the sensitive data model
    # @return [BOOLEAN]
    attr_accessor :is_sensitive

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'key': :'key',
        'lifecycle_state': :'lifecycleState',
        'sensitive_data_model_id': :'sensitiveDataModelId',
        'relation_type': :'relationType',
        'parent': :'parent',
        'child': :'child',
        'is_sensitive': :'isSensitive'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'key': :'String',
        'lifecycle_state': :'String',
        'sensitive_data_model_id': :'String',
        'relation_type': :'String',
        'parent': :'OCI::DataSafe::Models::ColumnsInfo',
        'child': :'OCI::DataSafe::Models::ColumnsInfo',
        'is_sensitive': :'BOOLEAN'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :key The value to assign to the {#key} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :sensitive_data_model_id The value to assign to the {#sensitive_data_model_id} property
    # @option attributes [String] :relation_type The value to assign to the {#relation_type} property
    # @option attributes [OCI::DataSafe::Models::ColumnsInfo] :parent The value to assign to the {#parent} property
    # @option attributes [OCI::DataSafe::Models::ColumnsInfo] :child The value to assign to the {#child} property
    # @option attributes [BOOLEAN] :is_sensitive The value to assign to the {#is_sensitive} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.key = attributes[:'key'] if attributes[:'key']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.sensitive_data_model_id = attributes[:'sensitiveDataModelId'] if attributes[:'sensitiveDataModelId']

      raise 'You cannot provide both :sensitiveDataModelId and :sensitive_data_model_id' if attributes.key?(:'sensitiveDataModelId') && attributes.key?(:'sensitive_data_model_id')

      self.sensitive_data_model_id = attributes[:'sensitive_data_model_id'] if attributes[:'sensitive_data_model_id']

      self.relation_type = attributes[:'relationType'] if attributes[:'relationType']

      raise 'You cannot provide both :relationType and :relation_type' if attributes.key?(:'relationType') && attributes.key?(:'relation_type')

      self.relation_type = attributes[:'relation_type'] if attributes[:'relation_type']

      self.parent = attributes[:'parent'] if attributes[:'parent']

      self.child = attributes[:'child'] if attributes[:'child']

      self.is_sensitive = attributes[:'isSensitive'] unless attributes[:'isSensitive'].nil?

      raise 'You cannot provide both :isSensitive and :is_sensitive' if attributes.key?(:'isSensitive') && attributes.key?(:'is_sensitive')

      self.is_sensitive = attributes[:'is_sensitive'] unless attributes[:'is_sensitive'].nil?
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] lifecycle_state Object to be assigned
    def lifecycle_state=(lifecycle_state)
      # rubocop:disable Style/ConditionalAssignment
      if lifecycle_state && !LIFECYCLE_STATE_ENUM.include?(lifecycle_state)
        OCI.logger.debug("Unknown value for 'lifecycle_state' [" + lifecycle_state + "]. Mapping to 'LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @lifecycle_state = LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE
      else
        @lifecycle_state = lifecycle_state
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] relation_type Object to be assigned
    def relation_type=(relation_type)
      # rubocop:disable Style/ConditionalAssignment
      if relation_type && !RELATION_TYPE_ENUM.include?(relation_type)
        OCI.logger.debug("Unknown value for 'relation_type' [" + relation_type + "]. Mapping to 'RELATION_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @relation_type = RELATION_TYPE_UNKNOWN_ENUM_VALUE
      else
        @relation_type = relation_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        key == other.key &&
        lifecycle_state == other.lifecycle_state &&
        sensitive_data_model_id == other.sensitive_data_model_id &&
        relation_type == other.relation_type &&
        parent == other.parent &&
        child == other.child &&
        is_sensitive == other.is_sensitive
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
      [key, lifecycle_state, sensitive_data_model_id, relation_type, parent, child, is_sensitive].hash
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
