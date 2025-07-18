# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20200131
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # A summary of detailed information on responder execution.
  class CloudGuard::Models::ResponderExecutionSummary
    RESPONDER_RULE_TYPE_ENUM = [
      RESPONDER_RULE_TYPE_REMEDIATION = 'REMEDIATION'.freeze,
      RESPONDER_RULE_TYPE_NOTIFICATION = 'NOTIFICATION'.freeze,
      RESPONDER_RULE_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    RESPONDER_EXECUTION_STATUS_ENUM = [
      RESPONDER_EXECUTION_STATUS_STARTED = 'STARTED'.freeze,
      RESPONDER_EXECUTION_STATUS_AWAITING_CONFIRMATION = 'AWAITING_CONFIRMATION'.freeze,
      RESPONDER_EXECUTION_STATUS_AWAITING_INPUT = 'AWAITING_INPUT'.freeze,
      RESPONDER_EXECUTION_STATUS_SUCCEEDED = 'SUCCEEDED'.freeze,
      RESPONDER_EXECUTION_STATUS_FAILED = 'FAILED'.freeze,
      RESPONDER_EXECUTION_STATUS_SKIPPED = 'SKIPPED'.freeze,
      RESPONDER_EXECUTION_STATUS_ALL = 'ALL'.freeze,
      RESPONDER_EXECUTION_STATUS_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    RESPONDER_EXECUTION_MODE_ENUM = [
      RESPONDER_EXECUTION_MODE_MANUAL = 'MANUAL'.freeze,
      RESPONDER_EXECUTION_MODE_AUTOMATED = 'AUTOMATED'.freeze,
      RESPONDER_EXECUTION_MODE_ALL = 'ALL'.freeze,
      RESPONDER_EXECUTION_MODE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The unique identifier of the responder execution
    # @return [String]
    attr_accessor :id

    # **[Required]** Responder rule ID for the responder execution
    # @return [String]
    attr_accessor :responder_rule_id

    # **[Required]** Rule type for the responder execution
    # @return [String]
    attr_reader :responder_rule_type

    # **[Required]** Rule name for the responder execution
    # @return [String]
    attr_accessor :responder_rule_name

    # **[Required]** Problem ID associated with the responder execution
    # @return [String]
    attr_accessor :problem_id

    # **[Required]** Problem name associated with the responder execution
    # @return [String]
    attr_accessor :problem_name

    # **[Required]** Region where the problem is found
    # @return [String]
    attr_accessor :region

    # **[Required]** Target ID of the problem for the responder execution
    # @return [String]
    attr_accessor :target_id

    # **[Required]** Compartment OCID of the problem for the responder execution
    # @return [String]
    attr_accessor :compartment_id

    # **[Required]** resource type of the problem for the responder execution
    # @return [String]
    attr_accessor :resource_type

    # **[Required]** Resource name of the problem for the responder execution.
    # @return [String]
    attr_accessor :resource_name

    # **[Required]** The date and time the responder execution was created. Format defined by RFC3339.
    # @return [DateTime]
    attr_accessor :time_created

    # The date and time the responder execution was updated. Format defined by RFC3339.
    # @return [DateTime]
    attr_accessor :time_completed

    # **[Required]** Current execution status of the responder
    # @return [String]
    attr_reader :responder_execution_status

    # **[Required]** Possible type of responder execution modes
    # @return [String]
    attr_reader :responder_execution_mode

    # Message about the responder execution.
    # @return [String]
    attr_accessor :message

    # @return [OCI::CloudGuard::Models::ResponderRuleExecutionDetails]
    attr_accessor :responder_rule_execution_details

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'id',
        'responder_rule_id': :'responderRuleId',
        'responder_rule_type': :'responderRuleType',
        'responder_rule_name': :'responderRuleName',
        'problem_id': :'problemId',
        'problem_name': :'problemName',
        'region': :'region',
        'target_id': :'targetId',
        'compartment_id': :'compartmentId',
        'resource_type': :'resourceType',
        'resource_name': :'resourceName',
        'time_created': :'timeCreated',
        'time_completed': :'timeCompleted',
        'responder_execution_status': :'responderExecutionStatus',
        'responder_execution_mode': :'responderExecutionMode',
        'message': :'message',
        'responder_rule_execution_details': :'responderRuleExecutionDetails'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'String',
        'responder_rule_id': :'String',
        'responder_rule_type': :'String',
        'responder_rule_name': :'String',
        'problem_id': :'String',
        'problem_name': :'String',
        'region': :'String',
        'target_id': :'String',
        'compartment_id': :'String',
        'resource_type': :'String',
        'resource_name': :'String',
        'time_created': :'DateTime',
        'time_completed': :'DateTime',
        'responder_execution_status': :'String',
        'responder_execution_mode': :'String',
        'message': :'String',
        'responder_rule_execution_details': :'OCI::CloudGuard::Models::ResponderRuleExecutionDetails'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :responder_rule_id The value to assign to the {#responder_rule_id} property
    # @option attributes [String] :responder_rule_type The value to assign to the {#responder_rule_type} property
    # @option attributes [String] :responder_rule_name The value to assign to the {#responder_rule_name} property
    # @option attributes [String] :problem_id The value to assign to the {#problem_id} property
    # @option attributes [String] :problem_name The value to assign to the {#problem_name} property
    # @option attributes [String] :region The value to assign to the {#region} property
    # @option attributes [String] :target_id The value to assign to the {#target_id} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [String] :resource_type The value to assign to the {#resource_type} property
    # @option attributes [String] :resource_name The value to assign to the {#resource_name} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [DateTime] :time_completed The value to assign to the {#time_completed} property
    # @option attributes [String] :responder_execution_status The value to assign to the {#responder_execution_status} property
    # @option attributes [String] :responder_execution_mode The value to assign to the {#responder_execution_mode} property
    # @option attributes [String] :message The value to assign to the {#message} property
    # @option attributes [OCI::CloudGuard::Models::ResponderRuleExecutionDetails] :responder_rule_execution_details The value to assign to the {#responder_rule_execution_details} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.id = attributes[:'id'] if attributes[:'id']

      self.responder_rule_id = attributes[:'responderRuleId'] if attributes[:'responderRuleId']

      raise 'You cannot provide both :responderRuleId and :responder_rule_id' if attributes.key?(:'responderRuleId') && attributes.key?(:'responder_rule_id')

      self.responder_rule_id = attributes[:'responder_rule_id'] if attributes[:'responder_rule_id']

      self.responder_rule_type = attributes[:'responderRuleType'] if attributes[:'responderRuleType']

      raise 'You cannot provide both :responderRuleType and :responder_rule_type' if attributes.key?(:'responderRuleType') && attributes.key?(:'responder_rule_type')

      self.responder_rule_type = attributes[:'responder_rule_type'] if attributes[:'responder_rule_type']

      self.responder_rule_name = attributes[:'responderRuleName'] if attributes[:'responderRuleName']

      raise 'You cannot provide both :responderRuleName and :responder_rule_name' if attributes.key?(:'responderRuleName') && attributes.key?(:'responder_rule_name')

      self.responder_rule_name = attributes[:'responder_rule_name'] if attributes[:'responder_rule_name']

      self.problem_id = attributes[:'problemId'] if attributes[:'problemId']

      raise 'You cannot provide both :problemId and :problem_id' if attributes.key?(:'problemId') && attributes.key?(:'problem_id')

      self.problem_id = attributes[:'problem_id'] if attributes[:'problem_id']

      self.problem_name = attributes[:'problemName'] if attributes[:'problemName']

      raise 'You cannot provide both :problemName and :problem_name' if attributes.key?(:'problemName') && attributes.key?(:'problem_name')

      self.problem_name = attributes[:'problem_name'] if attributes[:'problem_name']

      self.region = attributes[:'region'] if attributes[:'region']

      self.target_id = attributes[:'targetId'] if attributes[:'targetId']

      raise 'You cannot provide both :targetId and :target_id' if attributes.key?(:'targetId') && attributes.key?(:'target_id')

      self.target_id = attributes[:'target_id'] if attributes[:'target_id']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.resource_type = attributes[:'resourceType'] if attributes[:'resourceType']

      raise 'You cannot provide both :resourceType and :resource_type' if attributes.key?(:'resourceType') && attributes.key?(:'resource_type')

      self.resource_type = attributes[:'resource_type'] if attributes[:'resource_type']

      self.resource_name = attributes[:'resourceName'] if attributes[:'resourceName']

      raise 'You cannot provide both :resourceName and :resource_name' if attributes.key?(:'resourceName') && attributes.key?(:'resource_name')

      self.resource_name = attributes[:'resource_name'] if attributes[:'resource_name']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.time_completed = attributes[:'timeCompleted'] if attributes[:'timeCompleted']

      raise 'You cannot provide both :timeCompleted and :time_completed' if attributes.key?(:'timeCompleted') && attributes.key?(:'time_completed')

      self.time_completed = attributes[:'time_completed'] if attributes[:'time_completed']

      self.responder_execution_status = attributes[:'responderExecutionStatus'] if attributes[:'responderExecutionStatus']

      raise 'You cannot provide both :responderExecutionStatus and :responder_execution_status' if attributes.key?(:'responderExecutionStatus') && attributes.key?(:'responder_execution_status')

      self.responder_execution_status = attributes[:'responder_execution_status'] if attributes[:'responder_execution_status']

      self.responder_execution_mode = attributes[:'responderExecutionMode'] if attributes[:'responderExecutionMode']

      raise 'You cannot provide both :responderExecutionMode and :responder_execution_mode' if attributes.key?(:'responderExecutionMode') && attributes.key?(:'responder_execution_mode')

      self.responder_execution_mode = attributes[:'responder_execution_mode'] if attributes[:'responder_execution_mode']

      self.message = attributes[:'message'] if attributes[:'message']

      self.responder_rule_execution_details = attributes[:'responderRuleExecutionDetails'] if attributes[:'responderRuleExecutionDetails']

      raise 'You cannot provide both :responderRuleExecutionDetails and :responder_rule_execution_details' if attributes.key?(:'responderRuleExecutionDetails') && attributes.key?(:'responder_rule_execution_details')

      self.responder_rule_execution_details = attributes[:'responder_rule_execution_details'] if attributes[:'responder_rule_execution_details']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] responder_rule_type Object to be assigned
    def responder_rule_type=(responder_rule_type)
      # rubocop:disable Style/ConditionalAssignment
      if responder_rule_type && !RESPONDER_RULE_TYPE_ENUM.include?(responder_rule_type)
        OCI.logger.debug("Unknown value for 'responder_rule_type' [" + responder_rule_type + "]. Mapping to 'RESPONDER_RULE_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @responder_rule_type = RESPONDER_RULE_TYPE_UNKNOWN_ENUM_VALUE
      else
        @responder_rule_type = responder_rule_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] responder_execution_status Object to be assigned
    def responder_execution_status=(responder_execution_status)
      # rubocop:disable Style/ConditionalAssignment
      if responder_execution_status && !RESPONDER_EXECUTION_STATUS_ENUM.include?(responder_execution_status)
        OCI.logger.debug("Unknown value for 'responder_execution_status' [" + responder_execution_status + "]. Mapping to 'RESPONDER_EXECUTION_STATUS_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @responder_execution_status = RESPONDER_EXECUTION_STATUS_UNKNOWN_ENUM_VALUE
      else
        @responder_execution_status = responder_execution_status
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] responder_execution_mode Object to be assigned
    def responder_execution_mode=(responder_execution_mode)
      # rubocop:disable Style/ConditionalAssignment
      if responder_execution_mode && !RESPONDER_EXECUTION_MODE_ENUM.include?(responder_execution_mode)
        OCI.logger.debug("Unknown value for 'responder_execution_mode' [" + responder_execution_mode + "]. Mapping to 'RESPONDER_EXECUTION_MODE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @responder_execution_mode = RESPONDER_EXECUTION_MODE_UNKNOWN_ENUM_VALUE
      else
        @responder_execution_mode = responder_execution_mode
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
        responder_rule_id == other.responder_rule_id &&
        responder_rule_type == other.responder_rule_type &&
        responder_rule_name == other.responder_rule_name &&
        problem_id == other.problem_id &&
        problem_name == other.problem_name &&
        region == other.region &&
        target_id == other.target_id &&
        compartment_id == other.compartment_id &&
        resource_type == other.resource_type &&
        resource_name == other.resource_name &&
        time_created == other.time_created &&
        time_completed == other.time_completed &&
        responder_execution_status == other.responder_execution_status &&
        responder_execution_mode == other.responder_execution_mode &&
        message == other.message &&
        responder_rule_execution_details == other.responder_rule_execution_details
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
      [id, responder_rule_id, responder_rule_type, responder_rule_name, problem_id, problem_name, region, target_id, compartment_id, resource_type, resource_name, time_created, time_completed, responder_execution_status, responder_execution_mode, message, responder_rule_execution_details].hash
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
