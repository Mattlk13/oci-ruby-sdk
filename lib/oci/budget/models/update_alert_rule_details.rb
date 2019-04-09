# Copyright (c) 2016, 2019, Oracle and/or its affiliates. All rights reserved.

require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective
module OCI
  # The update alert rule details.
  class Budget::Models::UpdateAlertRuleDetails # rubocop:disable Metrics/LineLength
    TYPE_ENUM = [
      TYPE_ACTUAL = 'ACTUAL'.freeze,
      TYPE_FORECAST = 'FORECAST'.freeze
    ].freeze

    THRESHOLD_TYPE_ENUM = [
      THRESHOLD_TYPE_PERCENTAGE = 'PERCENTAGE'.freeze,
      THRESHOLD_TYPE_ABSOLUTE = 'ABSOLUTE'.freeze
    ].freeze

    # The name of the alert rule.
    # @return [String]
    attr_accessor :display_name

    # Type of alert. Valid values are ACTUAL (the alert will trigger based on actual usage) or
    # FORECAST (the alert will trigger based on predicted usage).
    #
    # @return [String]
    attr_reader :type

    # The threshold for triggering the alert expressed as a whole number or decimal value.
    # If thresholdType is ABSOLUTE, threshold can have at most 12 digits before the decimal point and up to 2 digits after the decimal point.
    # If thresholdType is PERCENTAGE, the maximum value is 10000 and can have up to 2 digits after the decimal point.
    #
    # @return [Float]
    attr_accessor :threshold

    # The type of threshold.
    # @return [String]
    attr_reader :threshold_type

    # The audience that will received the alert when it triggers.
    # @return [String]
    attr_accessor :recipients

    # The description of the alert rule
    # @return [String]
    attr_accessor :description

    # The message to be delivered to the recipients when alert is triggered
    # @return [String]
    attr_accessor :message

    # Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm).
    #
    # Example: `{\"Department\": \"Finance\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # Defined tags for this resource. Each key is predefined and scoped to a namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm).
    #
    # Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'displayName',
        'type': :'type',
        'threshold': :'threshold',
        'threshold_type': :'thresholdType',
        'recipients': :'recipients',
        'description': :'description',
        'message': :'message',
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
        'type': :'String',
        'threshold': :'Float',
        'threshold_type': :'String',
        'recipients': :'String',
        'description': :'String',
        'message': :'String',
        'freeform_tags': :'Hash<String, String>',
        'defined_tags': :'Hash<String, Hash<String, Object>>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/LineLength, Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :type The value to assign to the {#type} property
    # @option attributes [Float] :threshold The value to assign to the {#threshold} property
    # @option attributes [String] :threshold_type The value to assign to the {#threshold_type} property
    # @option attributes [String] :recipients The value to assign to the {#recipients} property
    # @option attributes [String] :description The value to assign to the {#description} property
    # @option attributes [String] :message The value to assign to the {#message} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.type = attributes[:'type'] if attributes[:'type']

      self.threshold = attributes[:'threshold'] if attributes[:'threshold']

      self.threshold_type = attributes[:'thresholdType'] if attributes[:'thresholdType']

      raise 'You cannot provide both :thresholdType and :threshold_type' if attributes.key?(:'thresholdType') && attributes.key?(:'threshold_type')

      self.threshold_type = attributes[:'threshold_type'] if attributes[:'threshold_type']

      self.recipients = attributes[:'recipients'] if attributes[:'recipients']

      self.description = attributes[:'description'] if attributes[:'description']

      self.message = attributes[:'message'] if attributes[:'message']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/LineLength, Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] type Object to be assigned
    def type=(type)
      # rubocop: disable Metrics/LineLength
      raise "Invalid value for 'type': this must be one of the values in TYPE_ENUM." if type && !TYPE_ENUM.include?(type)

      # rubocop: enable Metrics/LineLength
      @type = type
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] threshold_type Object to be assigned
    def threshold_type=(threshold_type)
      # rubocop: disable Metrics/LineLength
      raise "Invalid value for 'threshold_type': this must be one of the values in THRESHOLD_TYPE_ENUM." if threshold_type && !THRESHOLD_TYPE_ENUM.include?(threshold_type)

      # rubocop: enable Metrics/LineLength
      @threshold_type = threshold_type
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Metrics/LineLength, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        display_name == other.display_name &&
        type == other.type &&
        threshold == other.threshold &&
        threshold_type == other.threshold_type &&
        recipients == other.recipients &&
        description == other.description &&
        message == other.message &&
        freeform_tags == other.freeform_tags &&
        defined_tags == other.defined_tags
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Metrics/LineLength, Layout/EmptyLines

    # @see the `==` method
    # @param [Object] other the other object to be compared
    def eql?(other)
      self == other
    end

    # rubocop:disable Metrics/AbcSize, Metrics/LineLength, Layout/EmptyLines


    # Calculates hash code according to all attributes.
    # @return [Fixnum] Hash code
    def hash
      [display_name, type, threshold, threshold_type, recipients, description, message, freeform_tags, defined_tags].hash
    end
    # rubocop:enable Metrics/AbcSize, Metrics/LineLength, Layout/EmptyLines

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
# rubocop:enable Lint/UnneededCopDisableDirective