# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20221109
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Form field.
  class AiDocument::Models::DocumentField
    FIELD_TYPE_ENUM = [
      FIELD_TYPE_LINE_ITEM_GROUP = 'LINE_ITEM_GROUP'.freeze,
      FIELD_TYPE_LINE_ITEM = 'LINE_ITEM'.freeze,
      FIELD_TYPE_LINE_ITEM_FIELD = 'LINE_ITEM_FIELD'.freeze,
      FIELD_TYPE_KEY_VALUE = 'KEY_VALUE'.freeze,
      FIELD_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The field type.
    # @return [String]
    attr_reader :field_type

    # @return [OCI::AiDocument::Models::FieldLabel]
    attr_accessor :field_label

    # @return [OCI::AiDocument::Models::FieldName]
    attr_accessor :field_name

    # This attribute is required.
    # @return [OCI::AiDocument::Models::FieldValue]
    attr_accessor :field_value

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'field_type': :'fieldType',
        'field_label': :'fieldLabel',
        'field_name': :'fieldName',
        'field_value': :'fieldValue'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'field_type': :'String',
        'field_label': :'OCI::AiDocument::Models::FieldLabel',
        'field_name': :'OCI::AiDocument::Models::FieldName',
        'field_value': :'OCI::AiDocument::Models::FieldValue'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :field_type The value to assign to the {#field_type} property
    # @option attributes [OCI::AiDocument::Models::FieldLabel] :field_label The value to assign to the {#field_label} property
    # @option attributes [OCI::AiDocument::Models::FieldName] :field_name The value to assign to the {#field_name} property
    # @option attributes [OCI::AiDocument::Models::FieldValue] :field_value The value to assign to the {#field_value} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.field_type = attributes[:'fieldType'] if attributes[:'fieldType']

      raise 'You cannot provide both :fieldType and :field_type' if attributes.key?(:'fieldType') && attributes.key?(:'field_type')

      self.field_type = attributes[:'field_type'] if attributes[:'field_type']

      self.field_label = attributes[:'fieldLabel'] if attributes[:'fieldLabel']

      raise 'You cannot provide both :fieldLabel and :field_label' if attributes.key?(:'fieldLabel') && attributes.key?(:'field_label')

      self.field_label = attributes[:'field_label'] if attributes[:'field_label']

      self.field_name = attributes[:'fieldName'] if attributes[:'fieldName']

      raise 'You cannot provide both :fieldName and :field_name' if attributes.key?(:'fieldName') && attributes.key?(:'field_name')

      self.field_name = attributes[:'field_name'] if attributes[:'field_name']

      self.field_value = attributes[:'fieldValue'] if attributes[:'fieldValue']

      raise 'You cannot provide both :fieldValue and :field_value' if attributes.key?(:'fieldValue') && attributes.key?(:'field_value')

      self.field_value = attributes[:'field_value'] if attributes[:'field_value']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] field_type Object to be assigned
    def field_type=(field_type)
      # rubocop:disable Style/ConditionalAssignment
      if field_type && !FIELD_TYPE_ENUM.include?(field_type)
        OCI.logger.debug("Unknown value for 'field_type' [" + field_type + "]. Mapping to 'FIELD_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @field_type = FIELD_TYPE_UNKNOWN_ENUM_VALUE
      else
        @field_type = field_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        field_type == other.field_type &&
        field_label == other.field_label &&
        field_name == other.field_name &&
        field_value == other.field_value
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
      [field_type, field_label, field_name, field_value].hash
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
