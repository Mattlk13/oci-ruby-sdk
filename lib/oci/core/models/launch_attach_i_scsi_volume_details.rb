# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20160918
require 'date'
require_relative 'launch_attach_volume_details'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Details specific to ISCSI type volume attachments.
  class Core::Models::LaunchAttachIScsiVolumeDetails < Core::Models::LaunchAttachVolumeDetails
    ENCRYPTION_IN_TRANSIT_TYPE_ENUM = [
      ENCRYPTION_IN_TRANSIT_TYPE_NONE = 'NONE'.freeze,
      ENCRYPTION_IN_TRANSIT_TYPE_BM_ENCRYPTION_IN_TRANSIT = 'BM_ENCRYPTION_IN_TRANSIT'.freeze
    ].freeze

    # Whether to use CHAP authentication for the volume attachment. Defaults to false.
    #
    # @return [BOOLEAN]
    attr_accessor :use_chap

    # Refer the top-level definition of encryptionInTransitType.
    # The default value is NONE.
    #
    # @return [String]
    attr_reader :encryption_in_transit_type

    # Whether to enable Oracle Cloud Agent to perform the iSCSI login and logout commands after the volume attach or detach operations for non multipath-enabled iSCSI attachments.
    #
    # @return [BOOLEAN]
    attr_accessor :is_agent_auto_iscsi_login_enabled

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'device': :'device',
        'display_name': :'displayName',
        'is_read_only': :'isReadOnly',
        'is_shareable': :'isShareable',
        'type': :'type',
        'volume_id': :'volumeId',
        'launch_create_volume_details': :'launchCreateVolumeDetails',
        'use_chap': :'useChap',
        'encryption_in_transit_type': :'encryptionInTransitType',
        'is_agent_auto_iscsi_login_enabled': :'isAgentAutoIscsiLoginEnabled'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'device': :'String',
        'display_name': :'String',
        'is_read_only': :'BOOLEAN',
        'is_shareable': :'BOOLEAN',
        'type': :'String',
        'volume_id': :'String',
        'launch_create_volume_details': :'OCI::Core::Models::LaunchCreateVolumeDetails',
        'use_chap': :'BOOLEAN',
        'encryption_in_transit_type': :'String',
        'is_agent_auto_iscsi_login_enabled': :'BOOLEAN'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :device The value to assign to the {OCI::Core::Models::LaunchAttachVolumeDetails#device #device} proprety
    # @option attributes [String] :display_name The value to assign to the {OCI::Core::Models::LaunchAttachVolumeDetails#display_name #display_name} proprety
    # @option attributes [BOOLEAN] :is_read_only The value to assign to the {OCI::Core::Models::LaunchAttachVolumeDetails#is_read_only #is_read_only} proprety
    # @option attributes [BOOLEAN] :is_shareable The value to assign to the {OCI::Core::Models::LaunchAttachVolumeDetails#is_shareable #is_shareable} proprety
    # @option attributes [String] :volume_id The value to assign to the {OCI::Core::Models::LaunchAttachVolumeDetails#volume_id #volume_id} proprety
    # @option attributes [OCI::Core::Models::LaunchCreateVolumeDetails] :launch_create_volume_details The value to assign to the {OCI::Core::Models::LaunchAttachVolumeDetails#launch_create_volume_details #launch_create_volume_details} proprety
    # @option attributes [BOOLEAN] :use_chap The value to assign to the {#use_chap} property
    # @option attributes [String] :encryption_in_transit_type The value to assign to the {#encryption_in_transit_type} property
    # @option attributes [BOOLEAN] :is_agent_auto_iscsi_login_enabled The value to assign to the {#is_agent_auto_iscsi_login_enabled} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      attributes['type'] = 'iscsi'

      super(attributes)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.use_chap = attributes[:'useChap'] unless attributes[:'useChap'].nil?

      raise 'You cannot provide both :useChap and :use_chap' if attributes.key?(:'useChap') && attributes.key?(:'use_chap')

      self.use_chap = attributes[:'use_chap'] unless attributes[:'use_chap'].nil?

      self.encryption_in_transit_type = attributes[:'encryptionInTransitType'] if attributes[:'encryptionInTransitType']
      self.encryption_in_transit_type = "NONE" if encryption_in_transit_type.nil? && !attributes.key?(:'encryptionInTransitType') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :encryptionInTransitType and :encryption_in_transit_type' if attributes.key?(:'encryptionInTransitType') && attributes.key?(:'encryption_in_transit_type')

      self.encryption_in_transit_type = attributes[:'encryption_in_transit_type'] if attributes[:'encryption_in_transit_type']
      self.encryption_in_transit_type = "NONE" if encryption_in_transit_type.nil? && !attributes.key?(:'encryptionInTransitType') && !attributes.key?(:'encryption_in_transit_type') # rubocop:disable Style/StringLiterals

      self.is_agent_auto_iscsi_login_enabled = attributes[:'isAgentAutoIscsiLoginEnabled'] unless attributes[:'isAgentAutoIscsiLoginEnabled'].nil?

      raise 'You cannot provide both :isAgentAutoIscsiLoginEnabled and :is_agent_auto_iscsi_login_enabled' if attributes.key?(:'isAgentAutoIscsiLoginEnabled') && attributes.key?(:'is_agent_auto_iscsi_login_enabled')

      self.is_agent_auto_iscsi_login_enabled = attributes[:'is_agent_auto_iscsi_login_enabled'] unless attributes[:'is_agent_auto_iscsi_login_enabled'].nil?
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] encryption_in_transit_type Object to be assigned
    def encryption_in_transit_type=(encryption_in_transit_type)
      raise "Invalid value for 'encryption_in_transit_type': this must be one of the values in ENCRYPTION_IN_TRANSIT_TYPE_ENUM." if encryption_in_transit_type && !ENCRYPTION_IN_TRANSIT_TYPE_ENUM.include?(encryption_in_transit_type)

      @encryption_in_transit_type = encryption_in_transit_type
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        device == other.device &&
        display_name == other.display_name &&
        is_read_only == other.is_read_only &&
        is_shareable == other.is_shareable &&
        type == other.type &&
        volume_id == other.volume_id &&
        launch_create_volume_details == other.launch_create_volume_details &&
        use_chap == other.use_chap &&
        encryption_in_transit_type == other.encryption_in_transit_type &&
        is_agent_auto_iscsi_login_enabled == other.is_agent_auto_iscsi_login_enabled
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
      [device, display_name, is_read_only, is_shareable, type, volume_id, launch_create_volume_details, use_chap, encryption_in_transit_type, is_agent_auto_iscsi_login_enabled].hash
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
