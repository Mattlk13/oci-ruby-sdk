# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210224
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The details of the association.
  class CertificatesManagement::Models::Association
    LIFECYCLE_STATE_ENUM = [
      LIFECYCLE_STATE_CREATING = 'CREATING'.freeze,
      LIFECYCLE_STATE_ACTIVE = 'ACTIVE'.freeze,
      LIFECYCLE_STATE_UPDATING = 'UPDATING'.freeze,
      LIFECYCLE_STATE_DELETING = 'DELETING'.freeze,
      LIFECYCLE_STATE_FAILED = 'FAILED'.freeze,
      LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    ASSOCIATION_TYPE_ENUM = [
      ASSOCIATION_TYPE_CERTIFICATE = 'CERTIFICATE'.freeze,
      ASSOCIATION_TYPE_CERTIFICATE_AUTHORITY = 'CERTIFICATE_AUTHORITY'.freeze,
      ASSOCIATION_TYPE_CA_BUNDLE = 'CA_BUNDLE'.freeze,
      ASSOCIATION_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The OCID of the association.
    # @return [String]
    attr_accessor :id

    # **[Required]** A user-friendly name generated by the service for the association, expressed in a format that follows the pattern: [certificatesResourceEntityType]-[associatedResourceEntityType]-UUID.
    #
    # @return [String]
    attr_accessor :name

    # **[Required]** A property indicating when the association was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
    # Example: `2019-04-03T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_created

    # **[Required]** The current lifecycle state of the association.
    # @return [String]
    attr_reader :lifecycle_state

    # **[Required]** The OCID of the certificate-related resource associated with another Oracle Cloud Infrastructure resource.
    # @return [String]
    attr_accessor :certificates_resource_id

    # **[Required]** The OCID of the associated resource.
    # @return [String]
    attr_accessor :associated_resource_id

    # **[Required]** The compartment OCID of the association, which is strongly tied to the compartment OCID of the certificate-related resource.
    # @return [String]
    attr_accessor :compartment_id

    # **[Required]** Type of the association.
    # @return [String]
    attr_reader :association_type

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'id',
        'name': :'name',
        'time_created': :'timeCreated',
        'lifecycle_state': :'lifecycleState',
        'certificates_resource_id': :'certificatesResourceId',
        'associated_resource_id': :'associatedResourceId',
        'compartment_id': :'compartmentId',
        'association_type': :'associationType'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'String',
        'name': :'String',
        'time_created': :'DateTime',
        'lifecycle_state': :'String',
        'certificates_resource_id': :'String',
        'associated_resource_id': :'String',
        'compartment_id': :'String',
        'association_type': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :name The value to assign to the {#name} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :certificates_resource_id The value to assign to the {#certificates_resource_id} property
    # @option attributes [String] :associated_resource_id The value to assign to the {#associated_resource_id} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [String] :association_type The value to assign to the {#association_type} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.id = attributes[:'id'] if attributes[:'id']

      self.name = attributes[:'name'] if attributes[:'name']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.certificates_resource_id = attributes[:'certificatesResourceId'] if attributes[:'certificatesResourceId']

      raise 'You cannot provide both :certificatesResourceId and :certificates_resource_id' if attributes.key?(:'certificatesResourceId') && attributes.key?(:'certificates_resource_id')

      self.certificates_resource_id = attributes[:'certificates_resource_id'] if attributes[:'certificates_resource_id']

      self.associated_resource_id = attributes[:'associatedResourceId'] if attributes[:'associatedResourceId']

      raise 'You cannot provide both :associatedResourceId and :associated_resource_id' if attributes.key?(:'associatedResourceId') && attributes.key?(:'associated_resource_id')

      self.associated_resource_id = attributes[:'associated_resource_id'] if attributes[:'associated_resource_id']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.association_type = attributes[:'associationType'] if attributes[:'associationType']

      raise 'You cannot provide both :associationType and :association_type' if attributes.key?(:'associationType') && attributes.key?(:'association_type')

      self.association_type = attributes[:'association_type'] if attributes[:'association_type']
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
    # @param [Object] association_type Object to be assigned
    def association_type=(association_type)
      # rubocop:disable Style/ConditionalAssignment
      if association_type && !ASSOCIATION_TYPE_ENUM.include?(association_type)
        OCI.logger.debug("Unknown value for 'association_type' [" + association_type + "]. Mapping to 'ASSOCIATION_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @association_type = ASSOCIATION_TYPE_UNKNOWN_ENUM_VALUE
      else
        @association_type = association_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        id == other.id &&
        name == other.name &&
        time_created == other.time_created &&
        lifecycle_state == other.lifecycle_state &&
        certificates_resource_id == other.certificates_resource_id &&
        associated_resource_id == other.associated_resource_id &&
        compartment_id == other.compartment_id &&
        association_type == other.association_type
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
      [id, name, time_created, lifecycle_state, certificates_resource_id, associated_resource_id, compartment_id, association_type].hash
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
