# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210101
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Base class for the DetectAnomalies call. It contains the identifier that is
  # used for deciding what type of request this is.
  #
  # This class has direct subclasses. If you are using this class as input to a service operations then you should favor using a subclass over the base class
  class AiAnomalyDetection::Models::DetectAnomaliesDetails
    REQUEST_TYPE_ENUM = [
      REQUEST_TYPE_INLINE = 'INLINE'.freeze,
      REQUEST_TYPE_BASE64_ENCODED = 'BASE64_ENCODED'.freeze
    ].freeze

    # **[Required]** The OCID of the trained model.
    # @return [String]
    attr_accessor :model_id

    # **[Required]** Type of request. This parameter is automatically populated by classes generated
    # by the SDK. For raw curl requests, you must provide this field.
    #
    # @return [String]
    attr_reader :request_type

    # Sensitivity of the algorithm to detect anomalies - higher the value, more anomalies get flagged. The value estimated during training is used by default. You can choose to provide a custom value.
    # @return [Float]
    attr_accessor :sensitivity

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'model_id': :'modelId',
        'request_type': :'requestType',
        'sensitivity': :'sensitivity'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'model_id': :'String',
        'request_type': :'String',
        'sensitivity': :'Float'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Layout/EmptyLines, Metrics/PerceivedComplexity, Metrics/AbcSize


    # Given the hash representation of a subtype of this class,
    # use the info in the hash to return the class of the subtype.
    def self.get_subtype(object_hash)
      type = object_hash[:'requestType'] # rubocop:disable Style/SymbolLiteral

      return 'OCI::AiAnomalyDetection::Models::InlineDetectAnomaliesRequest' if type == 'INLINE'
      return 'OCI::AiAnomalyDetection::Models::EmbeddedDetectAnomaliesRequest' if type == 'BASE64_ENCODED'

      # TODO: Log a warning when the subtype is not found.
      'OCI::AiAnomalyDetection::Models::DetectAnomaliesDetails'
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Layout/EmptyLines, Metrics/PerceivedComplexity, Metrics/AbcSize

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :model_id The value to assign to the {#model_id} property
    # @option attributes [String] :request_type The value to assign to the {#request_type} property
    # @option attributes [Float] :sensitivity The value to assign to the {#sensitivity} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.model_id = attributes[:'modelId'] if attributes[:'modelId']

      raise 'You cannot provide both :modelId and :model_id' if attributes.key?(:'modelId') && attributes.key?(:'model_id')

      self.model_id = attributes[:'model_id'] if attributes[:'model_id']

      self.request_type = attributes[:'requestType'] if attributes[:'requestType']

      raise 'You cannot provide both :requestType and :request_type' if attributes.key?(:'requestType') && attributes.key?(:'request_type')

      self.request_type = attributes[:'request_type'] if attributes[:'request_type']

      self.sensitivity = attributes[:'sensitivity'] if attributes[:'sensitivity']
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
        model_id == other.model_id &&
        request_type == other.request_type &&
        sensitivity == other.sensitivity
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
      [model_id, request_type, sensitivity].hash
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
