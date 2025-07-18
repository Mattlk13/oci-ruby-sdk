# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210224
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # The details of the certificate. This object does not contain the certificate contents.
  class CertificatesManagement::Models::Certificate
    LIFECYCLE_STATE_ENUM = [
      LIFECYCLE_STATE_CREATING = 'CREATING'.freeze,
      LIFECYCLE_STATE_ACTIVE = 'ACTIVE'.freeze,
      LIFECYCLE_STATE_UPDATING = 'UPDATING'.freeze,
      LIFECYCLE_STATE_DELETING = 'DELETING'.freeze,
      LIFECYCLE_STATE_DELETED = 'DELETED'.freeze,
      LIFECYCLE_STATE_SCHEDULING_DELETION = 'SCHEDULING_DELETION'.freeze,
      LIFECYCLE_STATE_PENDING_DELETION = 'PENDING_DELETION'.freeze,
      LIFECYCLE_STATE_CANCELLING_DELETION = 'CANCELLING_DELETION'.freeze,
      LIFECYCLE_STATE_FAILED = 'FAILED'.freeze,
      LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    CONFIG_TYPE_ENUM = [
      CONFIG_TYPE_ISSUED_BY_INTERNAL_CA = 'ISSUED_BY_INTERNAL_CA'.freeze,
      CONFIG_TYPE_MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA = 'MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA'.freeze,
      CONFIG_TYPE_IMPORTED = 'IMPORTED'.freeze,
      CONFIG_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    KEY_ALGORITHM_ENUM = [
      KEY_ALGORITHM_RSA2048 = 'RSA2048'.freeze,
      KEY_ALGORITHM_RSA4096 = 'RSA4096'.freeze,
      KEY_ALGORITHM_ECDSA_P256 = 'ECDSA_P256'.freeze,
      KEY_ALGORITHM_ECDSA_P384 = 'ECDSA_P384'.freeze,
      KEY_ALGORITHM_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    SIGNATURE_ALGORITHM_ENUM = [
      SIGNATURE_ALGORITHM_SHA256_WITH_RSA = 'SHA256_WITH_RSA'.freeze,
      SIGNATURE_ALGORITHM_SHA384_WITH_RSA = 'SHA384_WITH_RSA'.freeze,
      SIGNATURE_ALGORITHM_SHA512_WITH_RSA = 'SHA512_WITH_RSA'.freeze,
      SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA = 'SHA256_WITH_ECDSA'.freeze,
      SIGNATURE_ALGORITHM_SHA384_WITH_ECDSA = 'SHA384_WITH_ECDSA'.freeze,
      SIGNATURE_ALGORITHM_SHA512_WITH_ECDSA = 'SHA512_WITH_ECDSA'.freeze,
      SIGNATURE_ALGORITHM_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    CERTIFICATE_PROFILE_TYPE_ENUM = [
      CERTIFICATE_PROFILE_TYPE_TLS_SERVER_OR_CLIENT = 'TLS_SERVER_OR_CLIENT'.freeze,
      CERTIFICATE_PROFILE_TYPE_TLS_SERVER = 'TLS_SERVER'.freeze,
      CERTIFICATE_PROFILE_TYPE_TLS_CLIENT = 'TLS_CLIENT'.freeze,
      CERTIFICATE_PROFILE_TYPE_TLS_CODE_SIGN = 'TLS_CODE_SIGN'.freeze,
      CERTIFICATE_PROFILE_TYPE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The OCID of the certificate.
    # @return [String]
    attr_accessor :id

    # The OCID of the certificate authority (CA) that issued the certificate.
    # @return [String]
    attr_accessor :issuer_certificate_authority_id

    # **[Required]** A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
    # @return [String]
    attr_accessor :name

    # A brief description of the certificate. Avoid entering confidential information.
    # @return [String]
    attr_accessor :description

    # A list of rules that control how the certificate is used and managed.
    # @return [Array<OCI::CertificatesManagement::Models::CertificateRule>]
    attr_accessor :certificate_rules

    # **[Required]** A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
    # Example: `2019-04-03T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_created

    # An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
    # Example: `2019-04-03T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_of_deletion

    # **[Required]** The current lifecycle state of the certificate.
    # @return [String]
    attr_reader :lifecycle_state

    # Additional information about the current lifecycle state of the certificate.
    # @return [String]
    attr_accessor :lifecycle_details

    # **[Required]** The OCID of the compartment where you want to create the certificate.
    # @return [String]
    attr_accessor :compartment_id

    # @return [OCI::CertificatesManagement::Models::CertificateVersionSummary]
    attr_accessor :current_version

    # @return [OCI::CertificatesManagement::Models::CertificateSubject]
    attr_accessor :subject

    # @return [OCI::CertificatesManagement::Models::CertificateRevocationListDetails]
    attr_accessor :certificate_revocation_list_details

    # **[Required]** The origin of the certificate.
    # @return [String]
    attr_reader :config_type

    # The algorithm used to create key pairs.
    # @return [String]
    attr_reader :key_algorithm

    # The algorithm used to sign the public key certificate.
    # @return [String]
    attr_reader :signature_algorithm

    # The name of the profile used to create the certificate, which depends on the type of certificate you need.
    # @return [String]
    attr_reader :certificate_profile_type

    # Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm).
    # Example: `{\"Department\": \"Finance\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # Defined tags for this resource. Each key is predefined and scoped to a namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/Content/General/Concepts/resourcetags.htm).
    # Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'id',
        'issuer_certificate_authority_id': :'issuerCertificateAuthorityId',
        'name': :'name',
        'description': :'description',
        'certificate_rules': :'certificateRules',
        'time_created': :'timeCreated',
        'time_of_deletion': :'timeOfDeletion',
        'lifecycle_state': :'lifecycleState',
        'lifecycle_details': :'lifecycleDetails',
        'compartment_id': :'compartmentId',
        'current_version': :'currentVersion',
        'subject': :'subject',
        'certificate_revocation_list_details': :'certificateRevocationListDetails',
        'config_type': :'configType',
        'key_algorithm': :'keyAlgorithm',
        'signature_algorithm': :'signatureAlgorithm',
        'certificate_profile_type': :'certificateProfileType',
        'freeform_tags': :'freeformTags',
        'defined_tags': :'definedTags'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'String',
        'issuer_certificate_authority_id': :'String',
        'name': :'String',
        'description': :'String',
        'certificate_rules': :'Array<OCI::CertificatesManagement::Models::CertificateRule>',
        'time_created': :'DateTime',
        'time_of_deletion': :'DateTime',
        'lifecycle_state': :'String',
        'lifecycle_details': :'String',
        'compartment_id': :'String',
        'current_version': :'OCI::CertificatesManagement::Models::CertificateVersionSummary',
        'subject': :'OCI::CertificatesManagement::Models::CertificateSubject',
        'certificate_revocation_list_details': :'OCI::CertificatesManagement::Models::CertificateRevocationListDetails',
        'config_type': :'String',
        'key_algorithm': :'String',
        'signature_algorithm': :'String',
        'certificate_profile_type': :'String',
        'freeform_tags': :'Hash<String, String>',
        'defined_tags': :'Hash<String, Hash<String, Object>>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :issuer_certificate_authority_id The value to assign to the {#issuer_certificate_authority_id} property
    # @option attributes [String] :name The value to assign to the {#name} property
    # @option attributes [String] :description The value to assign to the {#description} property
    # @option attributes [Array<OCI::CertificatesManagement::Models::CertificateRule>] :certificate_rules The value to assign to the {#certificate_rules} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [DateTime] :time_of_deletion The value to assign to the {#time_of_deletion} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :lifecycle_details The value to assign to the {#lifecycle_details} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [OCI::CertificatesManagement::Models::CertificateVersionSummary] :current_version The value to assign to the {#current_version} property
    # @option attributes [OCI::CertificatesManagement::Models::CertificateSubject] :subject The value to assign to the {#subject} property
    # @option attributes [OCI::CertificatesManagement::Models::CertificateRevocationListDetails] :certificate_revocation_list_details The value to assign to the {#certificate_revocation_list_details} property
    # @option attributes [String] :config_type The value to assign to the {#config_type} property
    # @option attributes [String] :key_algorithm The value to assign to the {#key_algorithm} property
    # @option attributes [String] :signature_algorithm The value to assign to the {#signature_algorithm} property
    # @option attributes [String] :certificate_profile_type The value to assign to the {#certificate_profile_type} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.id = attributes[:'id'] if attributes[:'id']

      self.issuer_certificate_authority_id = attributes[:'issuerCertificateAuthorityId'] if attributes[:'issuerCertificateAuthorityId']

      raise 'You cannot provide both :issuerCertificateAuthorityId and :issuer_certificate_authority_id' if attributes.key?(:'issuerCertificateAuthorityId') && attributes.key?(:'issuer_certificate_authority_id')

      self.issuer_certificate_authority_id = attributes[:'issuer_certificate_authority_id'] if attributes[:'issuer_certificate_authority_id']

      self.name = attributes[:'name'] if attributes[:'name']

      self.description = attributes[:'description'] if attributes[:'description']
      self.description = "null" if description.nil? && !attributes.key?(:'description') # rubocop:disable Style/StringLiterals

      self.certificate_rules = attributes[:'certificateRules'] if attributes[:'certificateRules']

      raise 'You cannot provide both :certificateRules and :certificate_rules' if attributes.key?(:'certificateRules') && attributes.key?(:'certificate_rules')

      self.certificate_rules = attributes[:'certificate_rules'] if attributes[:'certificate_rules']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.time_of_deletion = attributes[:'timeOfDeletion'] if attributes[:'timeOfDeletion']

      raise 'You cannot provide both :timeOfDeletion and :time_of_deletion' if attributes.key?(:'timeOfDeletion') && attributes.key?(:'time_of_deletion')

      self.time_of_deletion = attributes[:'time_of_deletion'] if attributes[:'time_of_deletion']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.lifecycle_details = attributes[:'lifecycleDetails'] if attributes[:'lifecycleDetails']
      self.lifecycle_details = "null" if lifecycle_details.nil? && !attributes.key?(:'lifecycleDetails') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :lifecycleDetails and :lifecycle_details' if attributes.key?(:'lifecycleDetails') && attributes.key?(:'lifecycle_details')

      self.lifecycle_details = attributes[:'lifecycle_details'] if attributes[:'lifecycle_details']
      self.lifecycle_details = "null" if lifecycle_details.nil? && !attributes.key?(:'lifecycleDetails') && !attributes.key?(:'lifecycle_details') # rubocop:disable Style/StringLiterals

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.current_version = attributes[:'currentVersion'] if attributes[:'currentVersion']

      raise 'You cannot provide both :currentVersion and :current_version' if attributes.key?(:'currentVersion') && attributes.key?(:'current_version')

      self.current_version = attributes[:'current_version'] if attributes[:'current_version']

      self.subject = attributes[:'subject'] if attributes[:'subject']

      self.certificate_revocation_list_details = attributes[:'certificateRevocationListDetails'] if attributes[:'certificateRevocationListDetails']

      raise 'You cannot provide both :certificateRevocationListDetails and :certificate_revocation_list_details' if attributes.key?(:'certificateRevocationListDetails') && attributes.key?(:'certificate_revocation_list_details')

      self.certificate_revocation_list_details = attributes[:'certificate_revocation_list_details'] if attributes[:'certificate_revocation_list_details']

      self.config_type = attributes[:'configType'] if attributes[:'configType']

      raise 'You cannot provide both :configType and :config_type' if attributes.key?(:'configType') && attributes.key?(:'config_type')

      self.config_type = attributes[:'config_type'] if attributes[:'config_type']

      self.key_algorithm = attributes[:'keyAlgorithm'] if attributes[:'keyAlgorithm']

      raise 'You cannot provide both :keyAlgorithm and :key_algorithm' if attributes.key?(:'keyAlgorithm') && attributes.key?(:'key_algorithm')

      self.key_algorithm = attributes[:'key_algorithm'] if attributes[:'key_algorithm']

      self.signature_algorithm = attributes[:'signatureAlgorithm'] if attributes[:'signatureAlgorithm']

      raise 'You cannot provide both :signatureAlgorithm and :signature_algorithm' if attributes.key?(:'signatureAlgorithm') && attributes.key?(:'signature_algorithm')

      self.signature_algorithm = attributes[:'signature_algorithm'] if attributes[:'signature_algorithm']

      self.certificate_profile_type = attributes[:'certificateProfileType'] if attributes[:'certificateProfileType']

      raise 'You cannot provide both :certificateProfileType and :certificate_profile_type' if attributes.key?(:'certificateProfileType') && attributes.key?(:'certificate_profile_type')

      self.certificate_profile_type = attributes[:'certificate_profile_type'] if attributes[:'certificate_profile_type']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']
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

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] config_type Object to be assigned
    def config_type=(config_type)
      # rubocop:disable Style/ConditionalAssignment
      if config_type && !CONFIG_TYPE_ENUM.include?(config_type)
        OCI.logger.debug("Unknown value for 'config_type' [" + config_type + "]. Mapping to 'CONFIG_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @config_type = CONFIG_TYPE_UNKNOWN_ENUM_VALUE
      else
        @config_type = config_type
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] key_algorithm Object to be assigned
    def key_algorithm=(key_algorithm)
      # rubocop:disable Style/ConditionalAssignment
      if key_algorithm && !KEY_ALGORITHM_ENUM.include?(key_algorithm)
        OCI.logger.debug("Unknown value for 'key_algorithm' [" + key_algorithm + "]. Mapping to 'KEY_ALGORITHM_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @key_algorithm = KEY_ALGORITHM_UNKNOWN_ENUM_VALUE
      else
        @key_algorithm = key_algorithm
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] signature_algorithm Object to be assigned
    def signature_algorithm=(signature_algorithm)
      # rubocop:disable Style/ConditionalAssignment
      if signature_algorithm && !SIGNATURE_ALGORITHM_ENUM.include?(signature_algorithm)
        OCI.logger.debug("Unknown value for 'signature_algorithm' [" + signature_algorithm + "]. Mapping to 'SIGNATURE_ALGORITHM_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @signature_algorithm = SIGNATURE_ALGORITHM_UNKNOWN_ENUM_VALUE
      else
        @signature_algorithm = signature_algorithm
      end
      # rubocop:enable Style/ConditionalAssignment
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] certificate_profile_type Object to be assigned
    def certificate_profile_type=(certificate_profile_type)
      # rubocop:disable Style/ConditionalAssignment
      if certificate_profile_type && !CERTIFICATE_PROFILE_TYPE_ENUM.include?(certificate_profile_type)
        OCI.logger.debug("Unknown value for 'certificate_profile_type' [" + certificate_profile_type + "]. Mapping to 'CERTIFICATE_PROFILE_TYPE_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @certificate_profile_type = CERTIFICATE_PROFILE_TYPE_UNKNOWN_ENUM_VALUE
      else
        @certificate_profile_type = certificate_profile_type
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
        issuer_certificate_authority_id == other.issuer_certificate_authority_id &&
        name == other.name &&
        description == other.description &&
        certificate_rules == other.certificate_rules &&
        time_created == other.time_created &&
        time_of_deletion == other.time_of_deletion &&
        lifecycle_state == other.lifecycle_state &&
        lifecycle_details == other.lifecycle_details &&
        compartment_id == other.compartment_id &&
        current_version == other.current_version &&
        subject == other.subject &&
        certificate_revocation_list_details == other.certificate_revocation_list_details &&
        config_type == other.config_type &&
        key_algorithm == other.key_algorithm &&
        signature_algorithm == other.signature_algorithm &&
        certificate_profile_type == other.certificate_profile_type &&
        freeform_tags == other.freeform_tags &&
        defined_tags == other.defined_tags
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
      [id, issuer_certificate_authority_id, name, description, certificate_rules, time_created, time_of_deletion, lifecycle_state, lifecycle_details, compartment_id, current_version, subject, certificate_revocation_list_details, config_type, key_algorithm, signature_algorithm, certificate_profile_type, freeform_tags, defined_tags].hash
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
