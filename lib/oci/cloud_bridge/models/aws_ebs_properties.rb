# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20220509
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # AWS EBS volume related properties.
  class CloudBridge::Models::AwsEbsProperties
    # Information about the volume attachments.
    # @return [Array<OCI::CloudBridge::Models::VolumeAttachment>]
    attr_accessor :attachments

    # The Availability Zone for the volume.
    # @return [String]
    attr_accessor :availability_zone

    # **[Required]** Indicates whether the volume is encrypted.
    # @return [BOOLEAN]
    attr_accessor :is_encrypted

    # The number of I/O operations per second.
    # @return [Integer]
    attr_accessor :iops

    # **[Required]** Indicates whether Amazon EBS Multi-Attach is enabled.
    # @return [BOOLEAN]
    attr_accessor :is_multi_attach_enabled

    # **[Required]** The size of the volume, in GiBs.
    # @return [Integer]
    attr_accessor :size_in_gi_bs

    # The volume state.
    # @return [String]
    attr_accessor :status

    # Any tags assigned to the volume.
    # @return [Array<OCI::CloudBridge::Models::Tag>]
    attr_accessor :tags

    # The throughput that the volume supports, in MiB/s.
    # @return [Integer]
    attr_accessor :throughput

    # **[Required]** The ID of the volume.
    # @return [String]
    attr_accessor :volume_key

    # **[Required]** The volume type.
    # @return [String]
    attr_accessor :volume_type

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'attachments': :'attachments',
        'availability_zone': :'availabilityZone',
        'is_encrypted': :'isEncrypted',
        'iops': :'iops',
        'is_multi_attach_enabled': :'isMultiAttachEnabled',
        'size_in_gi_bs': :'sizeInGiBs',
        'status': :'status',
        'tags': :'tags',
        'throughput': :'throughput',
        'volume_key': :'volumeKey',
        'volume_type': :'volumeType'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'attachments': :'Array<OCI::CloudBridge::Models::VolumeAttachment>',
        'availability_zone': :'String',
        'is_encrypted': :'BOOLEAN',
        'iops': :'Integer',
        'is_multi_attach_enabled': :'BOOLEAN',
        'size_in_gi_bs': :'Integer',
        'status': :'String',
        'tags': :'Array<OCI::CloudBridge::Models::Tag>',
        'throughput': :'Integer',
        'volume_key': :'String',
        'volume_type': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [Array<OCI::CloudBridge::Models::VolumeAttachment>] :attachments The value to assign to the {#attachments} property
    # @option attributes [String] :availability_zone The value to assign to the {#availability_zone} property
    # @option attributes [BOOLEAN] :is_encrypted The value to assign to the {#is_encrypted} property
    # @option attributes [Integer] :iops The value to assign to the {#iops} property
    # @option attributes [BOOLEAN] :is_multi_attach_enabled The value to assign to the {#is_multi_attach_enabled} property
    # @option attributes [Integer] :size_in_gi_bs The value to assign to the {#size_in_gi_bs} property
    # @option attributes [String] :status The value to assign to the {#status} property
    # @option attributes [Array<OCI::CloudBridge::Models::Tag>] :tags The value to assign to the {#tags} property
    # @option attributes [Integer] :throughput The value to assign to the {#throughput} property
    # @option attributes [String] :volume_key The value to assign to the {#volume_key} property
    # @option attributes [String] :volume_type The value to assign to the {#volume_type} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.attachments = attributes[:'attachments'] if attributes[:'attachments']

      self.availability_zone = attributes[:'availabilityZone'] if attributes[:'availabilityZone']

      raise 'You cannot provide both :availabilityZone and :availability_zone' if attributes.key?(:'availabilityZone') && attributes.key?(:'availability_zone')

      self.availability_zone = attributes[:'availability_zone'] if attributes[:'availability_zone']

      self.is_encrypted = attributes[:'isEncrypted'] unless attributes[:'isEncrypted'].nil?

      raise 'You cannot provide both :isEncrypted and :is_encrypted' if attributes.key?(:'isEncrypted') && attributes.key?(:'is_encrypted')

      self.is_encrypted = attributes[:'is_encrypted'] unless attributes[:'is_encrypted'].nil?

      self.iops = attributes[:'iops'] if attributes[:'iops']

      self.is_multi_attach_enabled = attributes[:'isMultiAttachEnabled'] unless attributes[:'isMultiAttachEnabled'].nil?

      raise 'You cannot provide both :isMultiAttachEnabled and :is_multi_attach_enabled' if attributes.key?(:'isMultiAttachEnabled') && attributes.key?(:'is_multi_attach_enabled')

      self.is_multi_attach_enabled = attributes[:'is_multi_attach_enabled'] unless attributes[:'is_multi_attach_enabled'].nil?

      self.size_in_gi_bs = attributes[:'sizeInGiBs'] if attributes[:'sizeInGiBs']

      raise 'You cannot provide both :sizeInGiBs and :size_in_gi_bs' if attributes.key?(:'sizeInGiBs') && attributes.key?(:'size_in_gi_bs')

      self.size_in_gi_bs = attributes[:'size_in_gi_bs'] if attributes[:'size_in_gi_bs']

      self.status = attributes[:'status'] if attributes[:'status']

      self.tags = attributes[:'tags'] if attributes[:'tags']

      self.throughput = attributes[:'throughput'] if attributes[:'throughput']

      self.volume_key = attributes[:'volumeKey'] if attributes[:'volumeKey']

      raise 'You cannot provide both :volumeKey and :volume_key' if attributes.key?(:'volumeKey') && attributes.key?(:'volume_key')

      self.volume_key = attributes[:'volume_key'] if attributes[:'volume_key']

      self.volume_type = attributes[:'volumeType'] if attributes[:'volumeType']

      raise 'You cannot provide both :volumeType and :volume_type' if attributes.key?(:'volumeType') && attributes.key?(:'volume_type')

      self.volume_type = attributes[:'volume_type'] if attributes[:'volume_type']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        attachments == other.attachments &&
        availability_zone == other.availability_zone &&
        is_encrypted == other.is_encrypted &&
        iops == other.iops &&
        is_multi_attach_enabled == other.is_multi_attach_enabled &&
        size_in_gi_bs == other.size_in_gi_bs &&
        status == other.status &&
        tags == other.tags &&
        throughput == other.throughput &&
        volume_key == other.volume_key &&
        volume_type == other.volume_type
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
      [attachments, availability_zone, is_encrypted, iops, is_multi_attach_enabled, size_in_gi_bs, status, tags, throughput, volume_key, volume_type].hash
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
