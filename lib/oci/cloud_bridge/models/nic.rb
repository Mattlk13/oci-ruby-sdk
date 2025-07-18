# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220509
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The VNIC configuration.
  class CloudBridge::Models::Nic
    # Provides a label and summary information for the device.
    # @return [String]
    attr_accessor :label

    # Switch name.
    # @return [String]
    attr_accessor :switch_name

    # Mac address of the VM.
    # @return [String]
    attr_accessor :mac_address

    # Mac address type.
    # @return [String]
    attr_accessor :mac_address_type

    # Network name.
    # @return [String]
    attr_accessor :network_name

    # List of IP addresses.
    # @return [Array<String>]
    attr_accessor :ip_addresses

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'label': :'label',
        'switch_name': :'switchName',
        'mac_address': :'macAddress',
        'mac_address_type': :'macAddressType',
        'network_name': :'networkName',
        'ip_addresses': :'ipAddresses'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'label': :'String',
        'switch_name': :'String',
        'mac_address': :'String',
        'mac_address_type': :'String',
        'network_name': :'String',
        'ip_addresses': :'Array<String>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :label The value to assign to the {#label} property
    # @option attributes [String] :switch_name The value to assign to the {#switch_name} property
    # @option attributes [String] :mac_address The value to assign to the {#mac_address} property
    # @option attributes [String] :mac_address_type The value to assign to the {#mac_address_type} property
    # @option attributes [String] :network_name The value to assign to the {#network_name} property
    # @option attributes [Array<String>] :ip_addresses The value to assign to the {#ip_addresses} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.label = attributes[:'label'] if attributes[:'label']

      self.switch_name = attributes[:'switchName'] if attributes[:'switchName']

      raise 'You cannot provide both :switchName and :switch_name' if attributes.key?(:'switchName') && attributes.key?(:'switch_name')

      self.switch_name = attributes[:'switch_name'] if attributes[:'switch_name']

      self.mac_address = attributes[:'macAddress'] if attributes[:'macAddress']

      raise 'You cannot provide both :macAddress and :mac_address' if attributes.key?(:'macAddress') && attributes.key?(:'mac_address')

      self.mac_address = attributes[:'mac_address'] if attributes[:'mac_address']

      self.mac_address_type = attributes[:'macAddressType'] if attributes[:'macAddressType']

      raise 'You cannot provide both :macAddressType and :mac_address_type' if attributes.key?(:'macAddressType') && attributes.key?(:'mac_address_type')

      self.mac_address_type = attributes[:'mac_address_type'] if attributes[:'mac_address_type']

      self.network_name = attributes[:'networkName'] if attributes[:'networkName']

      raise 'You cannot provide both :networkName and :network_name' if attributes.key?(:'networkName') && attributes.key?(:'network_name')

      self.network_name = attributes[:'network_name'] if attributes[:'network_name']

      self.ip_addresses = attributes[:'ipAddresses'] if attributes[:'ipAddresses']

      raise 'You cannot provide both :ipAddresses and :ip_addresses' if attributes.key?(:'ipAddresses') && attributes.key?(:'ip_addresses')

      self.ip_addresses = attributes[:'ip_addresses'] if attributes[:'ip_addresses']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        label == other.label &&
        switch_name == other.switch_name &&
        mac_address == other.mac_address &&
        mac_address_type == other.mac_address_type &&
        network_name == other.network_name &&
        ip_addresses == other.ip_addresses
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
      [label, switch_name, mac_address, mac_address_type, network_name, ip_addresses].hash
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
