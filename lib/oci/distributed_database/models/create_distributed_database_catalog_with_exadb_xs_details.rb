# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20250101
require 'date'
require_relative 'create_distributed_database_catalog_details'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Globally distributed database catalog based on exadbxs.
  class DistributedDatabase::Models::CreateDistributedDatabaseCatalogWithExadbXsDetails < DistributedDatabase::Models::CreateDistributedDatabaseCatalogDetails
    # **[Required]** The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the VmCluster.
    # @return [String]
    attr_accessor :vm_cluster_id

    # **[Required]** The admin password for the cataog associated with Globally distributed database.
    # @return [String]
    attr_accessor :admin_password

    # The collection of [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the peer VmClusterIds.
    # @return [Array<String>]
    attr_accessor :peer_vm_cluster_ids

    # The shard space name for the Globally distributed database. Shard space for existing shard cannot be changed, once shard is created.
    # Shard space name shall be used while creation of new shards.
    #
    # @return [String]
    attr_accessor :shard_space

    # The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/Content/KeyManagement/Concepts/keyoverview.htm#concepts). This parameter and `kmsKeyId` are required for Customer Managed Keys.
    # @return [String]
    attr_accessor :vault_id

    # The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
    # @return [String]
    attr_accessor :kms_key_id

    # The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions.
    #
    # @return [String]
    attr_accessor :kms_key_version_id

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'source': :'source',
        'vm_cluster_id': :'vmClusterId',
        'admin_password': :'adminPassword',
        'peer_vm_cluster_ids': :'peerVmClusterIds',
        'shard_space': :'shardSpace',
        'vault_id': :'vaultId',
        'kms_key_id': :'kmsKeyId',
        'kms_key_version_id': :'kmsKeyVersionId'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'source': :'String',
        'vm_cluster_id': :'String',
        'admin_password': :'String',
        'peer_vm_cluster_ids': :'Array<String>',
        'shard_space': :'String',
        'vault_id': :'String',
        'kms_key_id': :'String',
        'kms_key_version_id': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :vm_cluster_id The value to assign to the {#vm_cluster_id} property
    # @option attributes [String] :admin_password The value to assign to the {#admin_password} property
    # @option attributes [Array<String>] :peer_vm_cluster_ids The value to assign to the {#peer_vm_cluster_ids} property
    # @option attributes [String] :shard_space The value to assign to the {#shard_space} property
    # @option attributes [String] :vault_id The value to assign to the {#vault_id} property
    # @option attributes [String] :kms_key_id The value to assign to the {#kms_key_id} property
    # @option attributes [String] :kms_key_version_id The value to assign to the {#kms_key_version_id} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      attributes['source'] = 'EXADB_XS'

      super(attributes)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.vm_cluster_id = attributes[:'vmClusterId'] if attributes[:'vmClusterId']

      raise 'You cannot provide both :vmClusterId and :vm_cluster_id' if attributes.key?(:'vmClusterId') && attributes.key?(:'vm_cluster_id')

      self.vm_cluster_id = attributes[:'vm_cluster_id'] if attributes[:'vm_cluster_id']

      self.admin_password = attributes[:'adminPassword'] if attributes[:'adminPassword']

      raise 'You cannot provide both :adminPassword and :admin_password' if attributes.key?(:'adminPassword') && attributes.key?(:'admin_password')

      self.admin_password = attributes[:'admin_password'] if attributes[:'admin_password']

      self.peer_vm_cluster_ids = attributes[:'peerVmClusterIds'] if attributes[:'peerVmClusterIds']

      raise 'You cannot provide both :peerVmClusterIds and :peer_vm_cluster_ids' if attributes.key?(:'peerVmClusterIds') && attributes.key?(:'peer_vm_cluster_ids')

      self.peer_vm_cluster_ids = attributes[:'peer_vm_cluster_ids'] if attributes[:'peer_vm_cluster_ids']

      self.shard_space = attributes[:'shardSpace'] if attributes[:'shardSpace']

      raise 'You cannot provide both :shardSpace and :shard_space' if attributes.key?(:'shardSpace') && attributes.key?(:'shard_space')

      self.shard_space = attributes[:'shard_space'] if attributes[:'shard_space']

      self.vault_id = attributes[:'vaultId'] if attributes[:'vaultId']

      raise 'You cannot provide both :vaultId and :vault_id' if attributes.key?(:'vaultId') && attributes.key?(:'vault_id')

      self.vault_id = attributes[:'vault_id'] if attributes[:'vault_id']

      self.kms_key_id = attributes[:'kmsKeyId'] if attributes[:'kmsKeyId']

      raise 'You cannot provide both :kmsKeyId and :kms_key_id' if attributes.key?(:'kmsKeyId') && attributes.key?(:'kms_key_id')

      self.kms_key_id = attributes[:'kms_key_id'] if attributes[:'kms_key_id']

      self.kms_key_version_id = attributes[:'kmsKeyVersionId'] if attributes[:'kmsKeyVersionId']

      raise 'You cannot provide both :kmsKeyVersionId and :kms_key_version_id' if attributes.key?(:'kmsKeyVersionId') && attributes.key?(:'kms_key_version_id')

      self.kms_key_version_id = attributes[:'kms_key_version_id'] if attributes[:'kms_key_version_id']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        source == other.source &&
        vm_cluster_id == other.vm_cluster_id &&
        admin_password == other.admin_password &&
        peer_vm_cluster_ids == other.peer_vm_cluster_ids &&
        shard_space == other.shard_space &&
        vault_id == other.vault_id &&
        kms_key_id == other.kms_key_id &&
        kms_key_version_id == other.kms_key_version_id
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
      [source, vm_cluster_id, admin_password, peer_vm_cluster_ids, shard_space, vault_id, kms_key_id, kms_key_version_id].hash
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
