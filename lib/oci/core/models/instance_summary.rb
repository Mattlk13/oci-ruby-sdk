# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Condensed instance data when listing instances in an instance pool.
  class Core::Models::InstanceSummary
    # **[Required]** The OCID of the instance.
    # @return [String]
    attr_accessor :id

    # **[Required]** The availability domain the instance is running in.
    # @return [String]
    attr_accessor :availability_domain

    # **[Required]** The OCID of the compartment that contains the instance.
    # @return [String]
    attr_accessor :compartment_id

    # A user-friendly name. Does not have to be unique, and it's changeable.
    # Avoid entering confidential information.
    #
    # @return [String]
    attr_accessor :display_name

    # The fault domain the instance is running in.
    # @return [String]
    attr_accessor :fault_domain

    # **[Required]** The OCID of the instance confgiuration used to create the instance.
    # @return [String]
    attr_accessor :instance_configuration_id

    # **[Required]** The region that contains the availability domain the instance is running in.
    # @return [String]
    attr_accessor :region

    # The shape of an instance. The shape determines the number of CPUs, amount of memory,
    # and other resources allocated to the instance.
    #
    # You can enumerate all available shapes by calling {#list_shapes list_shapes}.
    #
    # @return [String]
    attr_accessor :shape

    # **[Required]** The current state of the instance pool instance.
    # @return [String]
    attr_accessor :state

    # **[Required]** The date and time the instance pool instance was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
    # Example: `2016-08-25T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_created

    # The load balancer backends that are configured for the instance pool instance.
    #
    # @return [Array<OCI::Core::Models::InstancePoolInstanceLoadBalancerBackend>]
    attr_accessor :load_balancer_backends

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'id',
        'availability_domain': :'availabilityDomain',
        'compartment_id': :'compartmentId',
        'display_name': :'displayName',
        'fault_domain': :'faultDomain',
        'instance_configuration_id': :'instanceConfigurationId',
        'region': :'region',
        'shape': :'shape',
        'state': :'state',
        'time_created': :'timeCreated',
        'load_balancer_backends': :'loadBalancerBackends'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'String',
        'availability_domain': :'String',
        'compartment_id': :'String',
        'display_name': :'String',
        'fault_domain': :'String',
        'instance_configuration_id': :'String',
        'region': :'String',
        'shape': :'String',
        'state': :'String',
        'time_created': :'DateTime',
        'load_balancer_backends': :'Array<OCI::Core::Models::InstancePoolInstanceLoadBalancerBackend>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :availability_domain The value to assign to the {#availability_domain} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :fault_domain The value to assign to the {#fault_domain} property
    # @option attributes [String] :instance_configuration_id The value to assign to the {#instance_configuration_id} property
    # @option attributes [String] :region The value to assign to the {#region} property
    # @option attributes [String] :shape The value to assign to the {#shape} property
    # @option attributes [String] :state The value to assign to the {#state} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [Array<OCI::Core::Models::InstancePoolInstanceLoadBalancerBackend>] :load_balancer_backends The value to assign to the {#load_balancer_backends} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.id = attributes[:'id'] if attributes[:'id']

      self.availability_domain = attributes[:'availabilityDomain'] if attributes[:'availabilityDomain']

      raise 'You cannot provide both :availabilityDomain and :availability_domain' if attributes.key?(:'availabilityDomain') && attributes.key?(:'availability_domain')

      self.availability_domain = attributes[:'availability_domain'] if attributes[:'availability_domain']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.fault_domain = attributes[:'faultDomain'] if attributes[:'faultDomain']

      raise 'You cannot provide both :faultDomain and :fault_domain' if attributes.key?(:'faultDomain') && attributes.key?(:'fault_domain')

      self.fault_domain = attributes[:'fault_domain'] if attributes[:'fault_domain']

      self.instance_configuration_id = attributes[:'instanceConfigurationId'] if attributes[:'instanceConfigurationId']

      raise 'You cannot provide both :instanceConfigurationId and :instance_configuration_id' if attributes.key?(:'instanceConfigurationId') && attributes.key?(:'instance_configuration_id')

      self.instance_configuration_id = attributes[:'instance_configuration_id'] if attributes[:'instance_configuration_id']

      self.region = attributes[:'region'] if attributes[:'region']

      self.shape = attributes[:'shape'] if attributes[:'shape']

      self.state = attributes[:'state'] if attributes[:'state']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.load_balancer_backends = attributes[:'loadBalancerBackends'] if attributes[:'loadBalancerBackends']

      raise 'You cannot provide both :loadBalancerBackends and :load_balancer_backends' if attributes.key?(:'loadBalancerBackends') && attributes.key?(:'load_balancer_backends')

      self.load_balancer_backends = attributes[:'load_balancer_backends'] if attributes[:'load_balancer_backends']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        id == other.id &&
        availability_domain == other.availability_domain &&
        compartment_id == other.compartment_id &&
        display_name == other.display_name &&
        fault_domain == other.fault_domain &&
        instance_configuration_id == other.instance_configuration_id &&
        region == other.region &&
        shape == other.shape &&
        state == other.state &&
        time_created == other.time_created &&
        load_balancer_backends == other.load_balancer_backends
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
      [id, availability_domain, compartment_id, display_name, fault_domain, instance_configuration_id, region, shape, state, time_created, load_balancer_backends].hash
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
