# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20221001
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # sub set of Job details data which need returns in list API
  class AiLanguage::Models::JobSummary
    # **[Required]** The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the job.
    # @return [String]
    attr_accessor :id

    # **[Required]** A user-friendly display name for the job.
    # @return [String]
    attr_accessor :display_name

    # A short description of the job.
    # @return [String]
    attr_accessor :description

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create the job.
    # @return [String]
    attr_accessor :compartment_id

    # The current state of the Speech Job.
    # @return [String]
    attr_accessor :lifecycle_state

    # A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
    # @return [String]
    attr_accessor :lifecycle_details

    # How much progress the operation has made, vs the total amount of work that must be performed.
    # @return [Integer]
    attr_accessor :percent_complete

    # Total number of documents given as input for prediction. For CSV this signifies number of rows and for TXT this signifies number of files.
    # @return [Integer]
    attr_accessor :total_documents

    # Number of documents still to process. For CSV this signifies number of rows and for TXT this signifies number of files.
    # @return [Integer]
    attr_accessor :pending_documents

    # Number of documents processed for prediction. For CSV this signifies number of rows and for TXT this signifies number of files.
    # @return [Integer]
    attr_accessor :completed_documents

    # Number of documents failed for prediction. For CSV this signifies number of rows and for TXT this signifies number of files.
    # @return [Integer]
    attr_accessor :failed_documents

    # warnings count
    # @return [Integer]
    attr_accessor :warnings_count

    # The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the job.
    # @return [String]
    attr_accessor :created_by

    # Job accepted time.
    # @return [DateTime]
    attr_accessor :time_accepted

    # Job started time.
    # @return [DateTime]
    attr_accessor :time_started

    # Job finished time.
    # @return [DateTime]
    attr_accessor :time_completed

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'id',
        'display_name': :'displayName',
        'description': :'description',
        'compartment_id': :'compartmentId',
        'lifecycle_state': :'lifecycleState',
        'lifecycle_details': :'lifecycleDetails',
        'percent_complete': :'percentComplete',
        'total_documents': :'totalDocuments',
        'pending_documents': :'pendingDocuments',
        'completed_documents': :'completedDocuments',
        'failed_documents': :'failedDocuments',
        'warnings_count': :'warningsCount',
        'created_by': :'createdBy',
        'time_accepted': :'timeAccepted',
        'time_started': :'timeStarted',
        'time_completed': :'timeCompleted'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'String',
        'display_name': :'String',
        'description': :'String',
        'compartment_id': :'String',
        'lifecycle_state': :'String',
        'lifecycle_details': :'String',
        'percent_complete': :'Integer',
        'total_documents': :'Integer',
        'pending_documents': :'Integer',
        'completed_documents': :'Integer',
        'failed_documents': :'Integer',
        'warnings_count': :'Integer',
        'created_by': :'String',
        'time_accepted': :'DateTime',
        'time_started': :'DateTime',
        'time_completed': :'DateTime'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :description The value to assign to the {#description} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :lifecycle_details The value to assign to the {#lifecycle_details} property
    # @option attributes [Integer] :percent_complete The value to assign to the {#percent_complete} property
    # @option attributes [Integer] :total_documents The value to assign to the {#total_documents} property
    # @option attributes [Integer] :pending_documents The value to assign to the {#pending_documents} property
    # @option attributes [Integer] :completed_documents The value to assign to the {#completed_documents} property
    # @option attributes [Integer] :failed_documents The value to assign to the {#failed_documents} property
    # @option attributes [Integer] :warnings_count The value to assign to the {#warnings_count} property
    # @option attributes [String] :created_by The value to assign to the {#created_by} property
    # @option attributes [DateTime] :time_accepted The value to assign to the {#time_accepted} property
    # @option attributes [DateTime] :time_started The value to assign to the {#time_started} property
    # @option attributes [DateTime] :time_completed The value to assign to the {#time_completed} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.id = attributes[:'id'] if attributes[:'id']

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.description = attributes[:'description'] if attributes[:'description']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.lifecycle_details = attributes[:'lifecycleDetails'] if attributes[:'lifecycleDetails']

      raise 'You cannot provide both :lifecycleDetails and :lifecycle_details' if attributes.key?(:'lifecycleDetails') && attributes.key?(:'lifecycle_details')

      self.lifecycle_details = attributes[:'lifecycle_details'] if attributes[:'lifecycle_details']

      self.percent_complete = attributes[:'percentComplete'] if attributes[:'percentComplete']

      raise 'You cannot provide both :percentComplete and :percent_complete' if attributes.key?(:'percentComplete') && attributes.key?(:'percent_complete')

      self.percent_complete = attributes[:'percent_complete'] if attributes[:'percent_complete']

      self.total_documents = attributes[:'totalDocuments'] if attributes[:'totalDocuments']

      raise 'You cannot provide both :totalDocuments and :total_documents' if attributes.key?(:'totalDocuments') && attributes.key?(:'total_documents')

      self.total_documents = attributes[:'total_documents'] if attributes[:'total_documents']

      self.pending_documents = attributes[:'pendingDocuments'] if attributes[:'pendingDocuments']

      raise 'You cannot provide both :pendingDocuments and :pending_documents' if attributes.key?(:'pendingDocuments') && attributes.key?(:'pending_documents')

      self.pending_documents = attributes[:'pending_documents'] if attributes[:'pending_documents']

      self.completed_documents = attributes[:'completedDocuments'] if attributes[:'completedDocuments']

      raise 'You cannot provide both :completedDocuments and :completed_documents' if attributes.key?(:'completedDocuments') && attributes.key?(:'completed_documents')

      self.completed_documents = attributes[:'completed_documents'] if attributes[:'completed_documents']

      self.failed_documents = attributes[:'failedDocuments'] if attributes[:'failedDocuments']

      raise 'You cannot provide both :failedDocuments and :failed_documents' if attributes.key?(:'failedDocuments') && attributes.key?(:'failed_documents')

      self.failed_documents = attributes[:'failed_documents'] if attributes[:'failed_documents']

      self.warnings_count = attributes[:'warningsCount'] if attributes[:'warningsCount']

      raise 'You cannot provide both :warningsCount and :warnings_count' if attributes.key?(:'warningsCount') && attributes.key?(:'warnings_count')

      self.warnings_count = attributes[:'warnings_count'] if attributes[:'warnings_count']

      self.created_by = attributes[:'createdBy'] if attributes[:'createdBy']

      raise 'You cannot provide both :createdBy and :created_by' if attributes.key?(:'createdBy') && attributes.key?(:'created_by')

      self.created_by = attributes[:'created_by'] if attributes[:'created_by']

      self.time_accepted = attributes[:'timeAccepted'] if attributes[:'timeAccepted']

      raise 'You cannot provide both :timeAccepted and :time_accepted' if attributes.key?(:'timeAccepted') && attributes.key?(:'time_accepted')

      self.time_accepted = attributes[:'time_accepted'] if attributes[:'time_accepted']

      self.time_started = attributes[:'timeStarted'] if attributes[:'timeStarted']

      raise 'You cannot provide both :timeStarted and :time_started' if attributes.key?(:'timeStarted') && attributes.key?(:'time_started')

      self.time_started = attributes[:'time_started'] if attributes[:'time_started']

      self.time_completed = attributes[:'timeCompleted'] if attributes[:'timeCompleted']

      raise 'You cannot provide both :timeCompleted and :time_completed' if attributes.key?(:'timeCompleted') && attributes.key?(:'time_completed')

      self.time_completed = attributes[:'time_completed'] if attributes[:'time_completed']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        id == other.id &&
        display_name == other.display_name &&
        description == other.description &&
        compartment_id == other.compartment_id &&
        lifecycle_state == other.lifecycle_state &&
        lifecycle_details == other.lifecycle_details &&
        percent_complete == other.percent_complete &&
        total_documents == other.total_documents &&
        pending_documents == other.pending_documents &&
        completed_documents == other.completed_documents &&
        failed_documents == other.failed_documents &&
        warnings_count == other.warnings_count &&
        created_by == other.created_by &&
        time_accepted == other.time_accepted &&
        time_started == other.time_started &&
        time_completed == other.time_completed
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
      [id, display_name, description, compartment_id, lifecycle_state, lifecycle_details, percent_complete, total_documents, pending_documents, completed_documents, failed_documents, warnings_count, created_by, time_accepted, time_started, time_completed].hash
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
