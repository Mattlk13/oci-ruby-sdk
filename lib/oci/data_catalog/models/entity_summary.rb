# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20190325
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Summary of an data entity. A representation of data with a set of attributes, normally representing a single
  # business entity. Synonymous with 'table' or 'view' in a database, or a single logical file structure
  # that one or many files may match.
  #
  class DataCatalog::Models::EntitySummary
    LIFECYCLE_STATE_ENUM = [
      LIFECYCLE_STATE_CREATING = 'CREATING'.freeze,
      LIFECYCLE_STATE_ACTIVE = 'ACTIVE'.freeze,
      LIFECYCLE_STATE_INACTIVE = 'INACTIVE'.freeze,
      LIFECYCLE_STATE_UPDATING = 'UPDATING'.freeze,
      LIFECYCLE_STATE_DELETING = 'DELETING'.freeze,
      LIFECYCLE_STATE_DELETED = 'DELETED'.freeze,
      LIFECYCLE_STATE_FAILED = 'FAILED'.freeze,
      LIFECYCLE_STATE_MOVING = 'MOVING'.freeze,
      LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** Unique data entity key that is immutable.
    # @return [String]
    attr_accessor :key

    # A user-friendly display name. Does not have to be unique, and it's changeable.
    # Avoid entering confidential information.
    #
    # @return [String]
    attr_accessor :display_name

    # Optional user friendly business name of the data entity. If set, this supplements the harvested display name of the object.
    # @return [String]
    attr_accessor :business_name

    # Detailed description of a data entity.
    # @return [String]
    attr_accessor :description

    # Property that identifies if the object is a physical object (materialized) or virtual/logical object
    # defined on other objects.
    #
    # @return [BOOLEAN]
    attr_accessor :is_logical

    # Property that identifies if an object is a sub object of a physical or materialized parent object.
    # @return [BOOLEAN]
    attr_accessor :is_partition

    # Unique key of the parent data asset.
    # @return [String]
    attr_accessor :data_asset_key

    # Key of the associated folder.
    # @return [String]
    attr_accessor :folder_key

    # Name of the associated folder. This name is harvested from the source data asset when the parent folder for the entiy is harvested.
    # @return [String]
    attr_accessor :folder_name

    # Unique external key of this object in the source system.
    # @return [String]
    attr_accessor :external_key

    # Key of the associated pattern if this is a logical entity.
    # @return [String]
    attr_accessor :pattern_key

    # The type of data entity object. Type keys can be found via the '/types' endpoint.
    # @return [String]
    attr_accessor :type_key

    # The expression realized after resolving qualifiers . Used in deriving this logical entity
    # @return [String]
    attr_accessor :realized_expression

    # Full path of the data entity.
    # @return [String]
    attr_accessor :path

    # The date and time the data entity was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
    # Example: `2019-03-25T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_created

    # The last time that any change was made to the data entity. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
    #
    # @return [DateTime]
    attr_accessor :time_updated

    # OCID of the user who updated this object in the data catalog.
    # @return [String]
    attr_accessor :updated_by_id

    # URI to the data entity instance in the API.
    # @return [String]
    attr_accessor :uri

    # URL of the data entity in the object store.
    # @return [String]
    attr_accessor :object_storage_url

    # State of the data entity.
    # @return [String]
    attr_reader :lifecycle_state

    # A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations,
    # see service documentation for details.
    #
    # @return [String]
    attr_accessor :lifecycle_details

    # A map of maps that contains the properties which are specific to the entity type. Each entity type
    # definition defines it's set of required and optional properties. The map keys are category names and the
    # values are maps of property name to property value. Every property is contained inside of a category. Most
    # data entities have required properties within the \"default\" category.
    # Example: `{\"properties\": { \"default\": { \"key1\": \"value1\"}}}`
    #
    # @return [Hash<String, Hash<String, String>>]
    attr_accessor :properties

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'key': :'key',
        'display_name': :'displayName',
        'business_name': :'businessName',
        'description': :'description',
        'is_logical': :'isLogical',
        'is_partition': :'isPartition',
        'data_asset_key': :'dataAssetKey',
        'folder_key': :'folderKey',
        'folder_name': :'folderName',
        'external_key': :'externalKey',
        'pattern_key': :'patternKey',
        'type_key': :'typeKey',
        'realized_expression': :'realizedExpression',
        'path': :'path',
        'time_created': :'timeCreated',
        'time_updated': :'timeUpdated',
        'updated_by_id': :'updatedById',
        'uri': :'uri',
        'object_storage_url': :'objectStorageUrl',
        'lifecycle_state': :'lifecycleState',
        'lifecycle_details': :'lifecycleDetails',
        'properties': :'properties'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'key': :'String',
        'display_name': :'String',
        'business_name': :'String',
        'description': :'String',
        'is_logical': :'BOOLEAN',
        'is_partition': :'BOOLEAN',
        'data_asset_key': :'String',
        'folder_key': :'String',
        'folder_name': :'String',
        'external_key': :'String',
        'pattern_key': :'String',
        'type_key': :'String',
        'realized_expression': :'String',
        'path': :'String',
        'time_created': :'DateTime',
        'time_updated': :'DateTime',
        'updated_by_id': :'String',
        'uri': :'String',
        'object_storage_url': :'String',
        'lifecycle_state': :'String',
        'lifecycle_details': :'String',
        'properties': :'Hash<String, Hash<String, String>>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :key The value to assign to the {#key} property
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :business_name The value to assign to the {#business_name} property
    # @option attributes [String] :description The value to assign to the {#description} property
    # @option attributes [BOOLEAN] :is_logical The value to assign to the {#is_logical} property
    # @option attributes [BOOLEAN] :is_partition The value to assign to the {#is_partition} property
    # @option attributes [String] :data_asset_key The value to assign to the {#data_asset_key} property
    # @option attributes [String] :folder_key The value to assign to the {#folder_key} property
    # @option attributes [String] :folder_name The value to assign to the {#folder_name} property
    # @option attributes [String] :external_key The value to assign to the {#external_key} property
    # @option attributes [String] :pattern_key The value to assign to the {#pattern_key} property
    # @option attributes [String] :type_key The value to assign to the {#type_key} property
    # @option attributes [String] :realized_expression The value to assign to the {#realized_expression} property
    # @option attributes [String] :path The value to assign to the {#path} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [DateTime] :time_updated The value to assign to the {#time_updated} property
    # @option attributes [String] :updated_by_id The value to assign to the {#updated_by_id} property
    # @option attributes [String] :uri The value to assign to the {#uri} property
    # @option attributes [String] :object_storage_url The value to assign to the {#object_storage_url} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :lifecycle_details The value to assign to the {#lifecycle_details} property
    # @option attributes [Hash<String, Hash<String, String>>] :properties The value to assign to the {#properties} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.key = attributes[:'key'] if attributes[:'key']

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.business_name = attributes[:'businessName'] if attributes[:'businessName']

      raise 'You cannot provide both :businessName and :business_name' if attributes.key?(:'businessName') && attributes.key?(:'business_name')

      self.business_name = attributes[:'business_name'] if attributes[:'business_name']

      self.description = attributes[:'description'] if attributes[:'description']

      self.is_logical = attributes[:'isLogical'] unless attributes[:'isLogical'].nil?

      raise 'You cannot provide both :isLogical and :is_logical' if attributes.key?(:'isLogical') && attributes.key?(:'is_logical')

      self.is_logical = attributes[:'is_logical'] unless attributes[:'is_logical'].nil?

      self.is_partition = attributes[:'isPartition'] unless attributes[:'isPartition'].nil?

      raise 'You cannot provide both :isPartition and :is_partition' if attributes.key?(:'isPartition') && attributes.key?(:'is_partition')

      self.is_partition = attributes[:'is_partition'] unless attributes[:'is_partition'].nil?

      self.data_asset_key = attributes[:'dataAssetKey'] if attributes[:'dataAssetKey']

      raise 'You cannot provide both :dataAssetKey and :data_asset_key' if attributes.key?(:'dataAssetKey') && attributes.key?(:'data_asset_key')

      self.data_asset_key = attributes[:'data_asset_key'] if attributes[:'data_asset_key']

      self.folder_key = attributes[:'folderKey'] if attributes[:'folderKey']

      raise 'You cannot provide both :folderKey and :folder_key' if attributes.key?(:'folderKey') && attributes.key?(:'folder_key')

      self.folder_key = attributes[:'folder_key'] if attributes[:'folder_key']

      self.folder_name = attributes[:'folderName'] if attributes[:'folderName']

      raise 'You cannot provide both :folderName and :folder_name' if attributes.key?(:'folderName') && attributes.key?(:'folder_name')

      self.folder_name = attributes[:'folder_name'] if attributes[:'folder_name']

      self.external_key = attributes[:'externalKey'] if attributes[:'externalKey']

      raise 'You cannot provide both :externalKey and :external_key' if attributes.key?(:'externalKey') && attributes.key?(:'external_key')

      self.external_key = attributes[:'external_key'] if attributes[:'external_key']

      self.pattern_key = attributes[:'patternKey'] if attributes[:'patternKey']

      raise 'You cannot provide both :patternKey and :pattern_key' if attributes.key?(:'patternKey') && attributes.key?(:'pattern_key')

      self.pattern_key = attributes[:'pattern_key'] if attributes[:'pattern_key']

      self.type_key = attributes[:'typeKey'] if attributes[:'typeKey']

      raise 'You cannot provide both :typeKey and :type_key' if attributes.key?(:'typeKey') && attributes.key?(:'type_key')

      self.type_key = attributes[:'type_key'] if attributes[:'type_key']

      self.realized_expression = attributes[:'realizedExpression'] if attributes[:'realizedExpression']

      raise 'You cannot provide both :realizedExpression and :realized_expression' if attributes.key?(:'realizedExpression') && attributes.key?(:'realized_expression')

      self.realized_expression = attributes[:'realized_expression'] if attributes[:'realized_expression']

      self.path = attributes[:'path'] if attributes[:'path']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.time_updated = attributes[:'timeUpdated'] if attributes[:'timeUpdated']

      raise 'You cannot provide both :timeUpdated and :time_updated' if attributes.key?(:'timeUpdated') && attributes.key?(:'time_updated')

      self.time_updated = attributes[:'time_updated'] if attributes[:'time_updated']

      self.updated_by_id = attributes[:'updatedById'] if attributes[:'updatedById']

      raise 'You cannot provide both :updatedById and :updated_by_id' if attributes.key?(:'updatedById') && attributes.key?(:'updated_by_id')

      self.updated_by_id = attributes[:'updated_by_id'] if attributes[:'updated_by_id']

      self.uri = attributes[:'uri'] if attributes[:'uri']

      self.object_storage_url = attributes[:'objectStorageUrl'] if attributes[:'objectStorageUrl']

      raise 'You cannot provide both :objectStorageUrl and :object_storage_url' if attributes.key?(:'objectStorageUrl') && attributes.key?(:'object_storage_url')

      self.object_storage_url = attributes[:'object_storage_url'] if attributes[:'object_storage_url']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.lifecycle_details = attributes[:'lifecycleDetails'] if attributes[:'lifecycleDetails']

      raise 'You cannot provide both :lifecycleDetails and :lifecycle_details' if attributes.key?(:'lifecycleDetails') && attributes.key?(:'lifecycle_details')

      self.lifecycle_details = attributes[:'lifecycle_details'] if attributes[:'lifecycle_details']

      self.properties = attributes[:'properties'] if attributes[:'properties']
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

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        key == other.key &&
        display_name == other.display_name &&
        business_name == other.business_name &&
        description == other.description &&
        is_logical == other.is_logical &&
        is_partition == other.is_partition &&
        data_asset_key == other.data_asset_key &&
        folder_key == other.folder_key &&
        folder_name == other.folder_name &&
        external_key == other.external_key &&
        pattern_key == other.pattern_key &&
        type_key == other.type_key &&
        realized_expression == other.realized_expression &&
        path == other.path &&
        time_created == other.time_created &&
        time_updated == other.time_updated &&
        updated_by_id == other.updated_by_id &&
        uri == other.uri &&
        object_storage_url == other.object_storage_url &&
        lifecycle_state == other.lifecycle_state &&
        lifecycle_details == other.lifecycle_details &&
        properties == other.properties
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
      [key, display_name, business_name, description, is_logical, is_partition, data_asset_key, folder_key, folder_name, external_key, pattern_key, type_key, realized_expression, path, time_created, time_updated, updated_by_id, uri, object_storage_url, lifecycle_state, lifecycle_details, properties].hash
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
