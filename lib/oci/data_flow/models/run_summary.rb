# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200129
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # A summary of the run.
  #
  class DataFlow::Models::RunSummary
    LANGUAGE_ENUM = [
      LANGUAGE_SCALA = 'SCALA'.freeze,
      LANGUAGE_JAVA = 'JAVA'.freeze,
      LANGUAGE_PYTHON = 'PYTHON'.freeze,
      LANGUAGE_SQL = 'SQL'.freeze,
      LANGUAGE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    LIFECYCLE_STATE_ENUM = [
      LIFECYCLE_STATE_ACCEPTED = 'ACCEPTED'.freeze,
      LIFECYCLE_STATE_IN_PROGRESS = 'IN_PROGRESS'.freeze,
      LIFECYCLE_STATE_CANCELING = 'CANCELING'.freeze,
      LIFECYCLE_STATE_CANCELED = 'CANCELED'.freeze,
      LIFECYCLE_STATE_FAILED = 'FAILED'.freeze,
      LIFECYCLE_STATE_SUCCEEDED = 'SUCCEEDED'.freeze,
      LIFECYCLE_STATE_STOPPING = 'STOPPING'.freeze,
      LIFECYCLE_STATE_STOPPED = 'STOPPED'.freeze,
      LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    TYPE_ENUM = [
      TYPE_BATCH = 'BATCH'.freeze,
      TYPE_STREAMING = 'STREAMING'.freeze,
      TYPE_SESSION = 'SESSION'.freeze,
      TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The application ID.
    #
    # @return [String]
    attr_accessor :application_id

    # **[Required]** The OCID of a compartment.
    #
    # @return [String]
    attr_accessor :compartment_id

    # The data read by the run in bytes.
    #
    # @return [Integer]
    attr_accessor :data_read_in_bytes

    # The data written by the run in bytes.
    #
    # @return [Integer]
    attr_accessor :data_written_in_bytes

    # **[Required]** Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
    # Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # A user-friendly name. This name is not necessarily unique.
    #
    # @return [String]
    attr_accessor :display_name

    # **[Required]** Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
    # Example: `{\"Department\": \"Finance\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # **[Required]** The ID of a run.
    #
    # @return [String]
    attr_accessor :id

    # **[Required]** The Spark language.
    #
    # @return [String]
    attr_reader :language

    # The detailed messages about the lifecycle state.
    #
    # @return [String]
    attr_accessor :lifecycle_details

    # **[Required]** The current state of this run.
    #
    # @return [String]
    attr_reader :lifecycle_state

    # Unique Oracle assigned identifier for the request.
    # If you need to contact Oracle about a particular request, please provide the request ID.
    #
    # @return [String]
    attr_accessor :opc_request_id

    # The OCID of the user who created the resource.
    #
    # @return [String]
    attr_accessor :owner_principal_id

    # The username of the user who created the resource.  If the username of the owner does not exist,
    # `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
    #
    # @return [String]
    attr_accessor :owner_user_name

    # The OCID of a pool. Unique Id to indentify a dataflow pool resource.
    #
    # @return [String]
    attr_accessor :pool_id

    # The duration of the run in milliseconds.
    #
    # @return [Integer]
    attr_accessor :run_duration_in_milliseconds

    # The total number of oCPU requested by the run.
    #
    # @return [Integer]
    attr_accessor :total_o_cpu

    # **[Required]** The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
    # Example: `2018-04-03T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_created

    # **[Required]** The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
    # Example: `2018-04-03T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_updated

    # The Spark application processing type.
    #
    # @return [String]
    attr_reader :type

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'application_id': :'applicationId',
        'compartment_id': :'compartmentId',
        'data_read_in_bytes': :'dataReadInBytes',
        'data_written_in_bytes': :'dataWrittenInBytes',
        'defined_tags': :'definedTags',
        'display_name': :'displayName',
        'freeform_tags': :'freeformTags',
        'id': :'id',
        'language': :'language',
        'lifecycle_details': :'lifecycleDetails',
        'lifecycle_state': :'lifecycleState',
        'opc_request_id': :'opcRequestId',
        'owner_principal_id': :'ownerPrincipalId',
        'owner_user_name': :'ownerUserName',
        'pool_id': :'poolId',
        'run_duration_in_milliseconds': :'runDurationInMilliseconds',
        'total_o_cpu': :'totalOCpu',
        'time_created': :'timeCreated',
        'time_updated': :'timeUpdated',
        'type': :'type'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'application_id': :'String',
        'compartment_id': :'String',
        'data_read_in_bytes': :'Integer',
        'data_written_in_bytes': :'Integer',
        'defined_tags': :'Hash<String, Hash<String, Object>>',
        'display_name': :'String',
        'freeform_tags': :'Hash<String, String>',
        'id': :'String',
        'language': :'String',
        'lifecycle_details': :'String',
        'lifecycle_state': :'String',
        'opc_request_id': :'String',
        'owner_principal_id': :'String',
        'owner_user_name': :'String',
        'pool_id': :'String',
        'run_duration_in_milliseconds': :'Integer',
        'total_o_cpu': :'Integer',
        'time_created': :'DateTime',
        'time_updated': :'DateTime',
        'type': :'String'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :application_id The value to assign to the {#application_id} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [Integer] :data_read_in_bytes The value to assign to the {#data_read_in_bytes} property
    # @option attributes [Integer] :data_written_in_bytes The value to assign to the {#data_written_in_bytes} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :language The value to assign to the {#language} property
    # @option attributes [String] :lifecycle_details The value to assign to the {#lifecycle_details} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :opc_request_id The value to assign to the {#opc_request_id} property
    # @option attributes [String] :owner_principal_id The value to assign to the {#owner_principal_id} property
    # @option attributes [String] :owner_user_name The value to assign to the {#owner_user_name} property
    # @option attributes [String] :pool_id The value to assign to the {#pool_id} property
    # @option attributes [Integer] :run_duration_in_milliseconds The value to assign to the {#run_duration_in_milliseconds} property
    # @option attributes [Integer] :total_o_cpu The value to assign to the {#total_o_cpu} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [DateTime] :time_updated The value to assign to the {#time_updated} property
    # @option attributes [String] :type The value to assign to the {#type} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.application_id = attributes[:'applicationId'] if attributes[:'applicationId']

      raise 'You cannot provide both :applicationId and :application_id' if attributes.key?(:'applicationId') && attributes.key?(:'application_id')

      self.application_id = attributes[:'application_id'] if attributes[:'application_id']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.data_read_in_bytes = attributes[:'dataReadInBytes'] if attributes[:'dataReadInBytes']

      raise 'You cannot provide both :dataReadInBytes and :data_read_in_bytes' if attributes.key?(:'dataReadInBytes') && attributes.key?(:'data_read_in_bytes')

      self.data_read_in_bytes = attributes[:'data_read_in_bytes'] if attributes[:'data_read_in_bytes']

      self.data_written_in_bytes = attributes[:'dataWrittenInBytes'] if attributes[:'dataWrittenInBytes']

      raise 'You cannot provide both :dataWrittenInBytes and :data_written_in_bytes' if attributes.key?(:'dataWrittenInBytes') && attributes.key?(:'data_written_in_bytes')

      self.data_written_in_bytes = attributes[:'data_written_in_bytes'] if attributes[:'data_written_in_bytes']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.id = attributes[:'id'] if attributes[:'id']

      self.language = attributes[:'language'] if attributes[:'language']

      self.lifecycle_details = attributes[:'lifecycleDetails'] if attributes[:'lifecycleDetails']

      raise 'You cannot provide both :lifecycleDetails and :lifecycle_details' if attributes.key?(:'lifecycleDetails') && attributes.key?(:'lifecycle_details')

      self.lifecycle_details = attributes[:'lifecycle_details'] if attributes[:'lifecycle_details']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.opc_request_id = attributes[:'opcRequestId'] if attributes[:'opcRequestId']

      raise 'You cannot provide both :opcRequestId and :opc_request_id' if attributes.key?(:'opcRequestId') && attributes.key?(:'opc_request_id')

      self.opc_request_id = attributes[:'opc_request_id'] if attributes[:'opc_request_id']

      self.owner_principal_id = attributes[:'ownerPrincipalId'] if attributes[:'ownerPrincipalId']

      raise 'You cannot provide both :ownerPrincipalId and :owner_principal_id' if attributes.key?(:'ownerPrincipalId') && attributes.key?(:'owner_principal_id')

      self.owner_principal_id = attributes[:'owner_principal_id'] if attributes[:'owner_principal_id']

      self.owner_user_name = attributes[:'ownerUserName'] if attributes[:'ownerUserName']

      raise 'You cannot provide both :ownerUserName and :owner_user_name' if attributes.key?(:'ownerUserName') && attributes.key?(:'owner_user_name')

      self.owner_user_name = attributes[:'owner_user_name'] if attributes[:'owner_user_name']

      self.pool_id = attributes[:'poolId'] if attributes[:'poolId']

      raise 'You cannot provide both :poolId and :pool_id' if attributes.key?(:'poolId') && attributes.key?(:'pool_id')

      self.pool_id = attributes[:'pool_id'] if attributes[:'pool_id']

      self.run_duration_in_milliseconds = attributes[:'runDurationInMilliseconds'] if attributes[:'runDurationInMilliseconds']

      raise 'You cannot provide both :runDurationInMilliseconds and :run_duration_in_milliseconds' if attributes.key?(:'runDurationInMilliseconds') && attributes.key?(:'run_duration_in_milliseconds')

      self.run_duration_in_milliseconds = attributes[:'run_duration_in_milliseconds'] if attributes[:'run_duration_in_milliseconds']

      self.total_o_cpu = attributes[:'totalOCpu'] if attributes[:'totalOCpu']

      raise 'You cannot provide both :totalOCpu and :total_o_cpu' if attributes.key?(:'totalOCpu') && attributes.key?(:'total_o_cpu')

      self.total_o_cpu = attributes[:'total_o_cpu'] if attributes[:'total_o_cpu']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.time_updated = attributes[:'timeUpdated'] if attributes[:'timeUpdated']

      raise 'You cannot provide both :timeUpdated and :time_updated' if attributes.key?(:'timeUpdated') && attributes.key?(:'time_updated')

      self.time_updated = attributes[:'time_updated'] if attributes[:'time_updated']

      self.type = attributes[:'type'] if attributes[:'type']
      self.type = "BATCH" if type.nil? && !attributes.key?(:'type') # rubocop:disable Style/StringLiterals
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] language Object to be assigned
    def language=(language)
      # rubocop:disable Style/ConditionalAssignment
      if language && !LANGUAGE_ENUM.include?(language)
        OCI.logger.debug("Unknown value for 'language' [" + language + "]. Mapping to 'LANGUAGE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @language = LANGUAGE_UNKNOWN_ENUM_VALUE
      else
        @language = language
      end
      # rubocop:enable Style/ConditionalAssignment
    end

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
    # @param [Object] type Object to be assigned
    def type=(type)
      # rubocop:disable Style/ConditionalAssignment
      if type && !TYPE_ENUM.include?(type)
        OCI.logger.debug("Unknown value for 'type' [" + type + "]. Mapping to 'TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @type = TYPE_UNKNOWN_ENUM_VALUE
      else
        @type = type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        application_id == other.application_id &&
        compartment_id == other.compartment_id &&
        data_read_in_bytes == other.data_read_in_bytes &&
        data_written_in_bytes == other.data_written_in_bytes &&
        defined_tags == other.defined_tags &&
        display_name == other.display_name &&
        freeform_tags == other.freeform_tags &&
        id == other.id &&
        language == other.language &&
        lifecycle_details == other.lifecycle_details &&
        lifecycle_state == other.lifecycle_state &&
        opc_request_id == other.opc_request_id &&
        owner_principal_id == other.owner_principal_id &&
        owner_user_name == other.owner_user_name &&
        pool_id == other.pool_id &&
        run_duration_in_milliseconds == other.run_duration_in_milliseconds &&
        total_o_cpu == other.total_o_cpu &&
        time_created == other.time_created &&
        time_updated == other.time_updated &&
        type == other.type
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
      [application_id, compartment_id, data_read_in_bytes, data_written_in_bytes, defined_tags, display_name, freeform_tags, id, language, lifecycle_details, lifecycle_state, opc_request_id, owner_principal_id, owner_user_name, pool_id, run_duration_in_milliseconds, total_o_cpu, time_created, time_updated, type].hash
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
