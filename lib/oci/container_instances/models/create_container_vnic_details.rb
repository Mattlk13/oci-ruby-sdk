# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210415
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Information to create a virtual network interface card (VNIC) which gives
  # the containers on this container instance access to a virtual client network (VCN).
  #
  # You use this object when creating the primary VNIC during container instance launch or when creating a secondary VNIC.
  # This VNIC is created in the same compartment as the specified subnet on
  # behalf of the customer.
  #
  # The VNIC created by this call contains both the tags specified
  # in this object as well as any tags specified in the parent container instance.
  #
  class ContainerInstances::Models::CreateContainerVnicDetails
    # A user-friendly name for the VNIC. Does not have to be unique.
    # Avoid entering confidential information.
    #
    # @return [String]
    attr_accessor :display_name

    # The hostname for the VNIC's primary private IP. Used for DNS.
    #
    # @return [String]
    attr_accessor :hostname_label

    # Whether the VNIC should be assigned a public IP address.
    #
    # @return [BOOLEAN]
    attr_accessor :is_public_ip_assigned

    # Whether the source/destination check is disabled on the VNIC.
    #
    # @return [BOOLEAN]
    attr_accessor :skip_source_dest_check

    # A list of the OCIDs of the network security groups (NSGs) to add the VNIC to.
    #
    # @return [Array<String>]
    attr_accessor :nsg_ids

    # A private IP address of your choice to assign to the VNIC. Must be an
    # available IP address within the subnet's CIDR.
    #
    # @return [String]
    attr_accessor :private_ip

    # **[Required]** The OCID of the subnet to create the VNIC in.
    #
    # @return [String]
    attr_accessor :subnet_id

    # Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
    # Example: `{\"bar-key\": \"value\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # Defined tags for this resource. Each key is predefined and scoped to a namespace.
    # Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`.
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'displayName',
        'hostname_label': :'hostnameLabel',
        'is_public_ip_assigned': :'isPublicIpAssigned',
        'skip_source_dest_check': :'skipSourceDestCheck',
        'nsg_ids': :'nsgIds',
        'private_ip': :'privateIp',
        'subnet_id': :'subnetId',
        'freeform_tags': :'freeformTags',
        'defined_tags': :'definedTags'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'String',
        'hostname_label': :'String',
        'is_public_ip_assigned': :'BOOLEAN',
        'skip_source_dest_check': :'BOOLEAN',
        'nsg_ids': :'Array<String>',
        'private_ip': :'String',
        'subnet_id': :'String',
        'freeform_tags': :'Hash<String, String>',
        'defined_tags': :'Hash<String, Hash<String, Object>>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :hostname_label The value to assign to the {#hostname_label} property
    # @option attributes [BOOLEAN] :is_public_ip_assigned The value to assign to the {#is_public_ip_assigned} property
    # @option attributes [BOOLEAN] :skip_source_dest_check The value to assign to the {#skip_source_dest_check} property
    # @option attributes [Array<String>] :nsg_ids The value to assign to the {#nsg_ids} property
    # @option attributes [String] :private_ip The value to assign to the {#private_ip} property
    # @option attributes [String] :subnet_id The value to assign to the {#subnet_id} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.hostname_label = attributes[:'hostnameLabel'] if attributes[:'hostnameLabel']

      raise 'You cannot provide both :hostnameLabel and :hostname_label' if attributes.key?(:'hostnameLabel') && attributes.key?(:'hostname_label')

      self.hostname_label = attributes[:'hostname_label'] if attributes[:'hostname_label']

      self.is_public_ip_assigned = attributes[:'isPublicIpAssigned'] unless attributes[:'isPublicIpAssigned'].nil?

      raise 'You cannot provide both :isPublicIpAssigned and :is_public_ip_assigned' if attributes.key?(:'isPublicIpAssigned') && attributes.key?(:'is_public_ip_assigned')

      self.is_public_ip_assigned = attributes[:'is_public_ip_assigned'] unless attributes[:'is_public_ip_assigned'].nil?

      self.skip_source_dest_check = attributes[:'skipSourceDestCheck'] unless attributes[:'skipSourceDestCheck'].nil?
      self.skip_source_dest_check = false if skip_source_dest_check.nil? && !attributes.key?(:'skipSourceDestCheck') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :skipSourceDestCheck and :skip_source_dest_check' if attributes.key?(:'skipSourceDestCheck') && attributes.key?(:'skip_source_dest_check')

      self.skip_source_dest_check = attributes[:'skip_source_dest_check'] unless attributes[:'skip_source_dest_check'].nil?
      self.skip_source_dest_check = false if skip_source_dest_check.nil? && !attributes.key?(:'skipSourceDestCheck') && !attributes.key?(:'skip_source_dest_check') # rubocop:disable Style/StringLiterals

      self.nsg_ids = attributes[:'nsgIds'] if attributes[:'nsgIds']

      raise 'You cannot provide both :nsgIds and :nsg_ids' if attributes.key?(:'nsgIds') && attributes.key?(:'nsg_ids')

      self.nsg_ids = attributes[:'nsg_ids'] if attributes[:'nsg_ids']

      self.private_ip = attributes[:'privateIp'] if attributes[:'privateIp']

      raise 'You cannot provide both :privateIp and :private_ip' if attributes.key?(:'privateIp') && attributes.key?(:'private_ip')

      self.private_ip = attributes[:'private_ip'] if attributes[:'private_ip']

      self.subnet_id = attributes[:'subnetId'] if attributes[:'subnetId']

      raise 'You cannot provide both :subnetId and :subnet_id' if attributes.key?(:'subnetId') && attributes.key?(:'subnet_id')

      self.subnet_id = attributes[:'subnet_id'] if attributes[:'subnet_id']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']
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
        hostname_label == other.hostname_label &&
        is_public_ip_assigned == other.is_public_ip_assigned &&
        skip_source_dest_check == other.skip_source_dest_check &&
        nsg_ids == other.nsg_ids &&
        private_ip == other.private_ip &&
        subnet_id == other.subnet_id &&
        freeform_tags == other.freeform_tags &&
        defined_tags == other.defined_tags
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
      [display_name, hostname_label, is_public_ip_assigned, skip_source_dest_check, nsg_ids, private_ip, subnet_id, freeform_tags, defined_tags].hash
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
