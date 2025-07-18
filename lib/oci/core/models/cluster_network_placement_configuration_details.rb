# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The location for where the instance pools in a cluster network will place instances.
  class Core::Models::ClusterNetworkPlacementConfigurationDetails
    PLACEMENT_CONSTRAINT_ENUM = [
      PLACEMENT_CONSTRAINT_SINGLE_TIER = 'SINGLE_TIER'.freeze,
      PLACEMENT_CONSTRAINT_SINGLE_BLOCK = 'SINGLE_BLOCK'.freeze,
      PLACEMENT_CONSTRAINT_PACKED_DISTRIBUTION_MULTI_BLOCK = 'PACKED_DISTRIBUTION_MULTI_BLOCK'.freeze,
      PLACEMENT_CONSTRAINT_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The availability domain to place instances.
    #
    # Example: `Uocm:PHX-AD-1`
    #
    # @return [String]
    attr_accessor :availability_domain

    # The placement constraint when reserving hosts.
    # @return [String]
    attr_reader :placement_constraint

    # The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the primary subnet to place instances. This field is deprecated.
    # Use `primaryVnicSubnets` instead to set VNIC data for instances in the pool.
    #
    # @return [String]
    attr_accessor :primary_subnet_id

    # @return [OCI::Core::Models::InstancePoolPlacementPrimarySubnet]
    attr_accessor :primary_vnic_subnets

    # The set of secondary VNIC data for instances in the pool.
    # @return [Array<OCI::Core::Models::InstancePoolPlacementSecondaryVnicSubnet>]
    attr_accessor :secondary_vnic_subnets

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'availability_domain': :'availabilityDomain',
        'placement_constraint': :'placementConstraint',
        'primary_subnet_id': :'primarySubnetId',
        'primary_vnic_subnets': :'primaryVnicSubnets',
        'secondary_vnic_subnets': :'secondaryVnicSubnets'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'availability_domain': :'String',
        'placement_constraint': :'String',
        'primary_subnet_id': :'String',
        'primary_vnic_subnets': :'OCI::Core::Models::InstancePoolPlacementPrimarySubnet',
        'secondary_vnic_subnets': :'Array<OCI::Core::Models::InstancePoolPlacementSecondaryVnicSubnet>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :availability_domain The value to assign to the {#availability_domain} property
    # @option attributes [String] :placement_constraint The value to assign to the {#placement_constraint} property
    # @option attributes [String] :primary_subnet_id The value to assign to the {#primary_subnet_id} property
    # @option attributes [OCI::Core::Models::InstancePoolPlacementPrimarySubnet] :primary_vnic_subnets The value to assign to the {#primary_vnic_subnets} property
    # @option attributes [Array<OCI::Core::Models::InstancePoolPlacementSecondaryVnicSubnet>] :secondary_vnic_subnets The value to assign to the {#secondary_vnic_subnets} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.availability_domain = attributes[:'availabilityDomain'] if attributes[:'availabilityDomain']

      raise 'You cannot provide both :availabilityDomain and :availability_domain' if attributes.key?(:'availabilityDomain') && attributes.key?(:'availability_domain')

      self.availability_domain = attributes[:'availability_domain'] if attributes[:'availability_domain']

      self.placement_constraint = attributes[:'placementConstraint'] if attributes[:'placementConstraint']

      raise 'You cannot provide both :placementConstraint and :placement_constraint' if attributes.key?(:'placementConstraint') && attributes.key?(:'placement_constraint')

      self.placement_constraint = attributes[:'placement_constraint'] if attributes[:'placement_constraint']

      self.primary_subnet_id = attributes[:'primarySubnetId'] if attributes[:'primarySubnetId']

      raise 'You cannot provide both :primarySubnetId and :primary_subnet_id' if attributes.key?(:'primarySubnetId') && attributes.key?(:'primary_subnet_id')

      self.primary_subnet_id = attributes[:'primary_subnet_id'] if attributes[:'primary_subnet_id']

      self.primary_vnic_subnets = attributes[:'primaryVnicSubnets'] if attributes[:'primaryVnicSubnets']

      raise 'You cannot provide both :primaryVnicSubnets and :primary_vnic_subnets' if attributes.key?(:'primaryVnicSubnets') && attributes.key?(:'primary_vnic_subnets')

      self.primary_vnic_subnets = attributes[:'primary_vnic_subnets'] if attributes[:'primary_vnic_subnets']

      self.secondary_vnic_subnets = attributes[:'secondaryVnicSubnets'] if attributes[:'secondaryVnicSubnets']

      raise 'You cannot provide both :secondaryVnicSubnets and :secondary_vnic_subnets' if attributes.key?(:'secondaryVnicSubnets') && attributes.key?(:'secondary_vnic_subnets')

      self.secondary_vnic_subnets = attributes[:'secondary_vnic_subnets'] if attributes[:'secondary_vnic_subnets']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] placement_constraint Object to be assigned
    def placement_constraint=(placement_constraint)
      # rubocop:disable Style/ConditionalAssignment
      if placement_constraint && !PLACEMENT_CONSTRAINT_ENUM.include?(placement_constraint)
        OCI.logger.debug("Unknown value for 'placement_constraint' [" + placement_constraint + "]. Mapping to 'PLACEMENT_CONSTRAINT_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @placement_constraint = PLACEMENT_CONSTRAINT_UNKNOWN_ENUM_VALUE
      else
        @placement_constraint = placement_constraint
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        availability_domain == other.availability_domain &&
        placement_constraint == other.placement_constraint &&
        primary_subnet_id == other.primary_subnet_id &&
        primary_vnic_subnets == other.primary_vnic_subnets &&
        secondary_vnic_subnets == other.secondary_vnic_subnets
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
      [availability_domain, placement_constraint, primary_subnet_id, primary_vnic_subnets, secondary_vnic_subnets].hash
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
