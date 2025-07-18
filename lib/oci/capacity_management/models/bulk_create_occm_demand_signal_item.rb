# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20231107
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The occm demand signal item which will be used for the bulk creation api.
  #
  class CapacityManagement::Models::BulkCreateOccmDemandSignalItem
    REQUEST_TYPE_ENUM = [
      REQUEST_TYPE_DEMAND = 'DEMAND'.freeze
    ].freeze

    # **[Required]** The OCID of the correponding demand signal catalog resource.
    #
    # @return [String]
    attr_accessor :demand_signal_catalog_resource_id

    # **[Required]** The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
    #
    # @return [String]
    attr_reader :request_type

    # **[Required]** The name of region for which you want to request the OCI resource.
    #
    # @return [String]
    attr_accessor :region

    # The name of the availability domain for which you want to request the OCI resource. This is an optional parameter.
    #
    # @return [String]
    attr_accessor :availability_domain

    # **[Required]** The OCID of the tenancy for which you want to request the OCI resource for. This is an optional parameter.
    #
    # @return [String]
    attr_accessor :target_compartment_id

    # **[Required]** The quantity of the resource that you want to demand from OCI.
    #
    # @return [Integer]
    attr_accessor :demand_quantity

    # **[Required]** the date before which you would ideally like the OCI resource to be delivered to you.
    #
    # @return [DateTime]
    attr_accessor :time_needed_before

    # **[Required]** A map of various properties associated with the OCI resource.
    #
    # @return [Hash<String, String>]
    attr_accessor :resource_properties

    # This field will serve as notes section for you. You can use this section to convey a message to OCI regarding your resource request.
    #
    # NOTE: The previous value gets overwritten with the new one for this once updated.
    #
    # @return [String]
    attr_accessor :notes

    # Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
    # Example: `{\"bar-key\": \"value\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # Defined tags for this resource. Each key is predefined and scoped to a namespace.
    # Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'demand_signal_catalog_resource_id': :'demandSignalCatalogResourceId',
        'request_type': :'requestType',
        'region': :'region',
        'availability_domain': :'availabilityDomain',
        'target_compartment_id': :'targetCompartmentId',
        'demand_quantity': :'demandQuantity',
        'time_needed_before': :'timeNeededBefore',
        'resource_properties': :'resourceProperties',
        'notes': :'notes',
        'freeform_tags': :'freeformTags',
        'defined_tags': :'definedTags'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'demand_signal_catalog_resource_id': :'String',
        'request_type': :'String',
        'region': :'String',
        'availability_domain': :'String',
        'target_compartment_id': :'String',
        'demand_quantity': :'Integer',
        'time_needed_before': :'DateTime',
        'resource_properties': :'Hash<String, String>',
        'notes': :'String',
        'freeform_tags': :'Hash<String, String>',
        'defined_tags': :'Hash<String, Hash<String, Object>>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :demand_signal_catalog_resource_id The value to assign to the {#demand_signal_catalog_resource_id} property
    # @option attributes [String] :request_type The value to assign to the {#request_type} property
    # @option attributes [String] :region The value to assign to the {#region} property
    # @option attributes [String] :availability_domain The value to assign to the {#availability_domain} property
    # @option attributes [String] :target_compartment_id The value to assign to the {#target_compartment_id} property
    # @option attributes [Integer] :demand_quantity The value to assign to the {#demand_quantity} property
    # @option attributes [DateTime] :time_needed_before The value to assign to the {#time_needed_before} property
    # @option attributes [Hash<String, String>] :resource_properties The value to assign to the {#resource_properties} property
    # @option attributes [String] :notes The value to assign to the {#notes} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.demand_signal_catalog_resource_id = attributes[:'demandSignalCatalogResourceId'] if attributes[:'demandSignalCatalogResourceId']

      raise 'You cannot provide both :demandSignalCatalogResourceId and :demand_signal_catalog_resource_id' if attributes.key?(:'demandSignalCatalogResourceId') && attributes.key?(:'demand_signal_catalog_resource_id')

      self.demand_signal_catalog_resource_id = attributes[:'demand_signal_catalog_resource_id'] if attributes[:'demand_signal_catalog_resource_id']

      self.request_type = attributes[:'requestType'] if attributes[:'requestType']

      raise 'You cannot provide both :requestType and :request_type' if attributes.key?(:'requestType') && attributes.key?(:'request_type')

      self.request_type = attributes[:'request_type'] if attributes[:'request_type']

      self.region = attributes[:'region'] if attributes[:'region']

      self.availability_domain = attributes[:'availabilityDomain'] if attributes[:'availabilityDomain']

      raise 'You cannot provide both :availabilityDomain and :availability_domain' if attributes.key?(:'availabilityDomain') && attributes.key?(:'availability_domain')

      self.availability_domain = attributes[:'availability_domain'] if attributes[:'availability_domain']

      self.target_compartment_id = attributes[:'targetCompartmentId'] if attributes[:'targetCompartmentId']

      raise 'You cannot provide both :targetCompartmentId and :target_compartment_id' if attributes.key?(:'targetCompartmentId') && attributes.key?(:'target_compartment_id')

      self.target_compartment_id = attributes[:'target_compartment_id'] if attributes[:'target_compartment_id']

      self.demand_quantity = attributes[:'demandQuantity'] if attributes[:'demandQuantity']

      raise 'You cannot provide both :demandQuantity and :demand_quantity' if attributes.key?(:'demandQuantity') && attributes.key?(:'demand_quantity')

      self.demand_quantity = attributes[:'demand_quantity'] if attributes[:'demand_quantity']

      self.time_needed_before = attributes[:'timeNeededBefore'] if attributes[:'timeNeededBefore']

      raise 'You cannot provide both :timeNeededBefore and :time_needed_before' if attributes.key?(:'timeNeededBefore') && attributes.key?(:'time_needed_before')

      self.time_needed_before = attributes[:'time_needed_before'] if attributes[:'time_needed_before']

      self.resource_properties = attributes[:'resourceProperties'] if attributes[:'resourceProperties']

      raise 'You cannot provide both :resourceProperties and :resource_properties' if attributes.key?(:'resourceProperties') && attributes.key?(:'resource_properties')

      self.resource_properties = attributes[:'resource_properties'] if attributes[:'resource_properties']

      self.notes = attributes[:'notes'] if attributes[:'notes']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] request_type Object to be assigned
    def request_type=(request_type)
      raise "Invalid value for 'request_type': this must be one of the values in REQUEST_TYPE_ENUM." if request_type && !REQUEST_TYPE_ENUM.include?(request_type)

      @request_type = request_type
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        demand_signal_catalog_resource_id == other.demand_signal_catalog_resource_id &&
        request_type == other.request_type &&
        region == other.region &&
        availability_domain == other.availability_domain &&
        target_compartment_id == other.target_compartment_id &&
        demand_quantity == other.demand_quantity &&
        time_needed_before == other.time_needed_before &&
        resource_properties == other.resource_properties &&
        notes == other.notes &&
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
      [demand_signal_catalog_resource_id, request_type, region, availability_domain, target_compartment_id, demand_quantity, time_needed_before, resource_properties, notes, freeform_tags, defined_tags].hash
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
