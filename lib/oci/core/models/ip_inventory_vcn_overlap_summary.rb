# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Provides the VCN overlap details.
  #
  class Core::Models::IpInventoryVcnOverlapSummary
    # The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN .
    # @return [String]
    attr_accessor :overlapping_vcn_id

    # Name of the overlapping VCN.
    # @return [String]
    attr_accessor :overlapping_vcn_name

    # The overlapping CIDR prefix.
    # @return [String]
    attr_accessor :overlapping_cidr

    # CIDR prefix of the VCN.
    # @return [String]
    attr_accessor :cidr

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'overlapping_vcn_id': :'overlappingVcnId',
        'overlapping_vcn_name': :'overlappingVcnName',
        'overlapping_cidr': :'overlappingCidr',
        'cidr': :'cidr'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'overlapping_vcn_id': :'String',
        'overlapping_vcn_name': :'String',
        'overlapping_cidr': :'String',
        'cidr': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :overlapping_vcn_id The value to assign to the {#overlapping_vcn_id} property
    # @option attributes [String] :overlapping_vcn_name The value to assign to the {#overlapping_vcn_name} property
    # @option attributes [String] :overlapping_cidr The value to assign to the {#overlapping_cidr} property
    # @option attributes [String] :cidr The value to assign to the {#cidr} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.overlapping_vcn_id = attributes[:'overlappingVcnId'] if attributes[:'overlappingVcnId']

      raise 'You cannot provide both :overlappingVcnId and :overlapping_vcn_id' if attributes.key?(:'overlappingVcnId') && attributes.key?(:'overlapping_vcn_id')

      self.overlapping_vcn_id = attributes[:'overlapping_vcn_id'] if attributes[:'overlapping_vcn_id']

      self.overlapping_vcn_name = attributes[:'overlappingVcnName'] if attributes[:'overlappingVcnName']

      raise 'You cannot provide both :overlappingVcnName and :overlapping_vcn_name' if attributes.key?(:'overlappingVcnName') && attributes.key?(:'overlapping_vcn_name')

      self.overlapping_vcn_name = attributes[:'overlapping_vcn_name'] if attributes[:'overlapping_vcn_name']

      self.overlapping_cidr = attributes[:'overlappingCidr'] if attributes[:'overlappingCidr']

      raise 'You cannot provide both :overlappingCidr and :overlapping_cidr' if attributes.key?(:'overlappingCidr') && attributes.key?(:'overlapping_cidr')

      self.overlapping_cidr = attributes[:'overlapping_cidr'] if attributes[:'overlapping_cidr']

      self.cidr = attributes[:'cidr'] if attributes[:'cidr']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        overlapping_vcn_id == other.overlapping_vcn_id &&
        overlapping_vcn_name == other.overlapping_vcn_name &&
        overlapping_cidr == other.overlapping_cidr &&
        cidr == other.cidr
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
      [overlapping_vcn_id, overlapping_vcn_name, overlapping_cidr, cidr].hash
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
