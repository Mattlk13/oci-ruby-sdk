# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20250228
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Preferences to send notifications on the task activities.
  class FleetAppsManagement::Models::TaskNotificationPreferences
    # Enables notification on pause.
    # @return [BOOLEAN]
    attr_accessor :should_notify_on_pause

    # Enables or disables notification on Task Failures.
    # @return [BOOLEAN]
    attr_accessor :should_notify_on_task_failure

    # Enables or disables notification on Task Success.
    # @return [BOOLEAN]
    attr_accessor :should_notify_on_task_success

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'should_notify_on_pause': :'shouldNotifyOnPause',
        'should_notify_on_task_failure': :'shouldNotifyOnTaskFailure',
        'should_notify_on_task_success': :'shouldNotifyOnTaskSuccess'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'should_notify_on_pause': :'BOOLEAN',
        'should_notify_on_task_failure': :'BOOLEAN',
        'should_notify_on_task_success': :'BOOLEAN'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [BOOLEAN] :should_notify_on_pause The value to assign to the {#should_notify_on_pause} property
    # @option attributes [BOOLEAN] :should_notify_on_task_failure The value to assign to the {#should_notify_on_task_failure} property
    # @option attributes [BOOLEAN] :should_notify_on_task_success The value to assign to the {#should_notify_on_task_success} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.should_notify_on_pause = attributes[:'shouldNotifyOnPause'] unless attributes[:'shouldNotifyOnPause'].nil?
      self.should_notify_on_pause = false if should_notify_on_pause.nil? && !attributes.key?(:'shouldNotifyOnPause') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :shouldNotifyOnPause and :should_notify_on_pause' if attributes.key?(:'shouldNotifyOnPause') && attributes.key?(:'should_notify_on_pause')

      self.should_notify_on_pause = attributes[:'should_notify_on_pause'] unless attributes[:'should_notify_on_pause'].nil?
      self.should_notify_on_pause = false if should_notify_on_pause.nil? && !attributes.key?(:'shouldNotifyOnPause') && !attributes.key?(:'should_notify_on_pause') # rubocop:disable Style/StringLiterals

      self.should_notify_on_task_failure = attributes[:'shouldNotifyOnTaskFailure'] unless attributes[:'shouldNotifyOnTaskFailure'].nil?
      self.should_notify_on_task_failure = false if should_notify_on_task_failure.nil? && !attributes.key?(:'shouldNotifyOnTaskFailure') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :shouldNotifyOnTaskFailure and :should_notify_on_task_failure' if attributes.key?(:'shouldNotifyOnTaskFailure') && attributes.key?(:'should_notify_on_task_failure')

      self.should_notify_on_task_failure = attributes[:'should_notify_on_task_failure'] unless attributes[:'should_notify_on_task_failure'].nil?
      self.should_notify_on_task_failure = false if should_notify_on_task_failure.nil? && !attributes.key?(:'shouldNotifyOnTaskFailure') && !attributes.key?(:'should_notify_on_task_failure') # rubocop:disable Style/StringLiterals

      self.should_notify_on_task_success = attributes[:'shouldNotifyOnTaskSuccess'] unless attributes[:'shouldNotifyOnTaskSuccess'].nil?
      self.should_notify_on_task_success = false if should_notify_on_task_success.nil? && !attributes.key?(:'shouldNotifyOnTaskSuccess') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :shouldNotifyOnTaskSuccess and :should_notify_on_task_success' if attributes.key?(:'shouldNotifyOnTaskSuccess') && attributes.key?(:'should_notify_on_task_success')

      self.should_notify_on_task_success = attributes[:'should_notify_on_task_success'] unless attributes[:'should_notify_on_task_success'].nil?
      self.should_notify_on_task_success = false if should_notify_on_task_success.nil? && !attributes.key?(:'shouldNotifyOnTaskSuccess') && !attributes.key?(:'should_notify_on_task_success') # rubocop:disable Style/StringLiterals
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        should_notify_on_pause == other.should_notify_on_pause &&
        should_notify_on_task_failure == other.should_notify_on_task_failure &&
        should_notify_on_task_success == other.should_notify_on_task_success
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
      [should_notify_on_pause, should_notify_on_task_failure, should_notify_on_task_success].hash
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
