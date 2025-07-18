# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Details about the IPv6 primary subnet.
  class Core::Models::InstancePoolPlacementPrimarySubnet
    # Whether to allocate an IPv6 address at instance and VNIC creation from an IPv6 enabled
    # subnet. Default: False. When provided you may optionally provide an IPv6 prefix
    # (`ipv6SubnetCidr`) of your choice to assign the IPv6 address from. If `ipv6SubnetCidr`
    # is not provided then an IPv6 prefix is chosen
    # for you.
    #
    # @return [BOOLEAN]
    attr_accessor :is_assign_ipv6_ip

    # A list of IPv6 prefix ranges from which the VNIC should be assigned an IPv6 address.
    # You can provide only the prefix ranges and OCI will select an available
    # address from the range. You can optionally choose to leave the prefix range empty
    # and instead provide the specific IPv6 address that should be used from within that range.
    #
    # @return [Array<OCI::Core::Models::InstancePoolPlacementIpv6AddressIpv6SubnetCidrDetails>]
    attr_accessor :ipv6_address_ipv6_subnet_cidr_pair_details

    # **[Required]** The subnet [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the secondary VNIC.
    # @return [String]
    attr_accessor :subnet_id

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'is_assign_ipv6_ip': :'isAssignIpv6Ip',
        'ipv6_address_ipv6_subnet_cidr_pair_details': :'ipv6AddressIpv6SubnetCidrPairDetails',
        'subnet_id': :'subnetId'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'is_assign_ipv6_ip': :'BOOLEAN',
        'ipv6_address_ipv6_subnet_cidr_pair_details': :'Array<OCI::Core::Models::InstancePoolPlacementIpv6AddressIpv6SubnetCidrDetails>',
        'subnet_id': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [BOOLEAN] :is_assign_ipv6_ip The value to assign to the {#is_assign_ipv6_ip} property
    # @option attributes [Array<OCI::Core::Models::InstancePoolPlacementIpv6AddressIpv6SubnetCidrDetails>] :ipv6_address_ipv6_subnet_cidr_pair_details The value to assign to the {#ipv6_address_ipv6_subnet_cidr_pair_details} property
    # @option attributes [String] :subnet_id The value to assign to the {#subnet_id} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      self.is_assign_ipv6_ip = attributes[:'isAssignIpv6Ip'] unless attributes[:'isAssignIpv6Ip'].nil?
      self.is_assign_ipv6_ip = false if is_assign_ipv6_ip.nil? && !attributes.key?(:'isAssignIpv6Ip') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :isAssignIpv6Ip and :is_assign_ipv6_ip' if attributes.key?(:'isAssignIpv6Ip') && attributes.key?(:'is_assign_ipv6_ip')

      self.is_assign_ipv6_ip = attributes[:'is_assign_ipv6_ip'] unless attributes[:'is_assign_ipv6_ip'].nil?
      self.is_assign_ipv6_ip = false if is_assign_ipv6_ip.nil? && !attributes.key?(:'isAssignIpv6Ip') && !attributes.key?(:'is_assign_ipv6_ip') # rubocop:disable Style/StringLiterals

      self.ipv6_address_ipv6_subnet_cidr_pair_details = attributes[:'ipv6AddressIpv6SubnetCidrPairDetails'] if attributes[:'ipv6AddressIpv6SubnetCidrPairDetails']

      raise 'You cannot provide both :ipv6AddressIpv6SubnetCidrPairDetails and :ipv6_address_ipv6_subnet_cidr_pair_details' if attributes.key?(:'ipv6AddressIpv6SubnetCidrPairDetails') && attributes.key?(:'ipv6_address_ipv6_subnet_cidr_pair_details')

      self.ipv6_address_ipv6_subnet_cidr_pair_details = attributes[:'ipv6_address_ipv6_subnet_cidr_pair_details'] if attributes[:'ipv6_address_ipv6_subnet_cidr_pair_details']

      self.subnet_id = attributes[:'subnetId'] if attributes[:'subnetId']

      raise 'You cannot provide both :subnetId and :subnet_id' if attributes.key?(:'subnetId') && attributes.key?(:'subnet_id')

      self.subnet_id = attributes[:'subnet_id'] if attributes[:'subnet_id']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        is_assign_ipv6_ip == other.is_assign_ipv6_ip &&
        ipv6_address_ipv6_subnet_cidr_pair_details == other.ipv6_address_ipv6_subnet_cidr_pair_details &&
        subnet_id == other.subnet_id
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
      [is_assign_ipv6_ip, ipv6_address_ipv6_subnet_cidr_pair_details, subnet_id].hash
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
