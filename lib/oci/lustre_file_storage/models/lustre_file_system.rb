# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20250228
require 'date'
require 'logger'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # A Lustre file system is a parallel file system that is used as a storage solution for HPC/AI/ML workloads.
  # For more information, see [File Storage with Lustre](https://docs.cloud.oracle.com/iaas/Content/lustre/home.htm).
  #
  # To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to
  # an administrator. If you're an administrator who needs to write policies to give users access, see
  # [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/policiesgs/get-started-with-policies.htm).
  #
  class LustreFileStorage::Models::LustreFileSystem
    LIFECYCLE_STATE_ENUM = [
      LIFECYCLE_STATE_CREATING = 'CREATING'.freeze,
      LIFECYCLE_STATE_UPDATING = 'UPDATING'.freeze,
      LIFECYCLE_STATE_ACTIVE = 'ACTIVE'.freeze,
      LIFECYCLE_STATE_INACTIVE = 'INACTIVE'.freeze,
      LIFECYCLE_STATE_DELETING = 'DELETING'.freeze,
      LIFECYCLE_STATE_DELETED = 'DELETED'.freeze,
      LIFECYCLE_STATE_FAILED = 'FAILED'.freeze,
      LIFECYCLE_STATE_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    PERFORMANCE_TIER_ENUM = [
      PERFORMANCE_TIER_MBPS_PER_TB_125 = 'MBPS_PER_TB_125'.freeze,
      PERFORMANCE_TIER_MBPS_PER_TB_250 = 'MBPS_PER_TB_250'.freeze,
      PERFORMANCE_TIER_MBPS_PER_TB_500 = 'MBPS_PER_TB_500'.freeze,
      PERFORMANCE_TIER_MBPS_PER_TB_1000 = 'MBPS_PER_TB_1000'.freeze,
      PERFORMANCE_TIER_UNKNOWN_ENUM_VALUE = 'UNKNOWN_ENUM_VALUE'.freeze
    ].freeze

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Lustre file system.
    # @return [String]
    attr_accessor :id

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the Lustre file system.
    # @return [String]
    attr_accessor :compartment_id

    # **[Required]** The availability domain the file system is in. May be unset
    # as a blank or NULL value.
    #
    # Example: `Uocm:PHX-AD-1`
    #
    # @return [String]
    attr_accessor :availability_domain

    # **[Required]** A user-friendly name. It does not have to be unique, and it is changeable.
    # Avoid entering confidential information.
    #
    # Example: `My Lustre file system`
    #
    #
    # @return [String]
    attr_accessor :display_name

    # **[Required]** Short description of the Lustre file system.
    # Avoid entering confidential information.
    #
    # @return [String]
    attr_accessor :file_system_description

    # **[Required]** The date and time the Lustre file system was created, expressed
    # in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.
    #
    # Example: `2024-04-25T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_created

    # **[Required]** The date and time the Lustre file system was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).
    #
    # Example: `2024-04-25T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_updated

    # **[Required]** The current state of the Lustre file system.
    # @return [String]
    attr_reader :lifecycle_state

    # A message that describes the current state of the Lustre file system in more detail. For example,
    # can be used to provide actionable information for a resource in the Failed state.
    #
    # @return [String]
    attr_accessor :lifecycle_details

    # **[Required]** Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
    #
    # Example: `{\"Department\": \"Finance\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # **[Required]** Defined tags for this resource. Each key is predefined and scoped to a namespace.
    # For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
    #
    # Example: `{\"Operations\": {\"CostCenter\": \"42\"}}`
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # **[Required]** System tags for this resource. Each key is predefined and scoped to a namespace.
    #
    # Example: `{\"orcl-cloud\": {\"free-tier-retained\": \"true\"}}`
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :system_tags

    # A list of Network Security Group [OCIDs](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) associated with this lustre file system.
    # A maximum of 5 is allowed.
    # Setting this to an empty array after the list is created removes the lustre file system from all NSGs.
    # For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/Content/Network/Concepts/securityrules.htm).
    #
    # @return [Array<String>]
    attr_accessor :nsg_ids

    # The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the KMS key used to encrypt the encryption keys associated with this file system.
    #
    # @return [String]
    attr_accessor :kms_key_id

    # **[Required]** Capacity of the Lustre file system in GB.
    # @return [Integer]
    attr_accessor :capacity_in_gbs

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the subnet the Lustre file system is in.
    # @return [String]
    attr_accessor :subnet_id

    # **[Required]** The Lustre file system performance tier. A value of `MBPS_PER_TB_125` represents 125 megabytes per second per terabyte.
    # @return [String]
    attr_reader :performance_tier

    # **[Required]** The IPv4 address of MGS (Lustre Management Service) used by clients to mount the file system. For example '10.0.0.4'.
    # @return [String]
    attr_accessor :management_service_address

    # **[Required]** The Lustre file system name. This is used in mount commands and other aspects of the client command line interface.
    # The default file system name is 'lustre'. The file system name is limited to 8 characters. Allowed characters are lower and upper case English letters, numbers, and '_'.
    #
    # @return [String]
    attr_accessor :file_system_name

    # **[Required]** Type of network used by clients to mount the file system.
    #
    # Example: `tcp`
    #
    # @return [String]
    attr_accessor :lnet

    # **[Required]** Major version of Lustre running in the Lustre file system.
    # Example: `2.15`
    #
    # @return [String]
    attr_accessor :major_version

    # The [OCID](https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the cluster placement group in which the Lustre file system exists.
    # @return [String]
    attr_accessor :cluster_placement_group_id

    # The date and time that the current billing cycle for the file system will end, expressed in
    # [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. After the current cycle ends,
    # this date is updated automatically to the next timestamp, which is 30 days later.
    # File systems deleted earlier than this time will still incur charges until the billing cycle ends.
    #
    # Example: `2016-08-25T21:10:29.600Z`
    #
    # @return [DateTime]
    attr_accessor :time_billing_cycle_end

    # This attribute is required.
    # @return [OCI::LustreFileStorage::Models::MaintenanceWindow]
    attr_accessor :maintenance_window

    # This attribute is required.
    # @return [OCI::LustreFileStorage::Models::RootSquashConfiguration]
    attr_accessor :root_squash_configuration

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'id',
        'compartment_id': :'compartmentId',
        'availability_domain': :'availabilityDomain',
        'display_name': :'displayName',
        'file_system_description': :'fileSystemDescription',
        'time_created': :'timeCreated',
        'time_updated': :'timeUpdated',
        'lifecycle_state': :'lifecycleState',
        'lifecycle_details': :'lifecycleDetails',
        'freeform_tags': :'freeformTags',
        'defined_tags': :'definedTags',
        'system_tags': :'systemTags',
        'nsg_ids': :'nsgIds',
        'kms_key_id': :'kmsKeyId',
        'capacity_in_gbs': :'capacityInGBs',
        'subnet_id': :'subnetId',
        'performance_tier': :'performanceTier',
        'management_service_address': :'managementServiceAddress',
        'file_system_name': :'fileSystemName',
        'lnet': :'lnet',
        'major_version': :'majorVersion',
        'cluster_placement_group_id': :'clusterPlacementGroupId',
        'time_billing_cycle_end': :'timeBillingCycleEnd',
        'maintenance_window': :'maintenanceWindow',
        'root_squash_configuration': :'rootSquashConfiguration'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'id': :'String',
        'compartment_id': :'String',
        'availability_domain': :'String',
        'display_name': :'String',
        'file_system_description': :'String',
        'time_created': :'DateTime',
        'time_updated': :'DateTime',
        'lifecycle_state': :'String',
        'lifecycle_details': :'String',
        'freeform_tags': :'Hash<String, String>',
        'defined_tags': :'Hash<String, Hash<String, Object>>',
        'system_tags': :'Hash<String, Hash<String, Object>>',
        'nsg_ids': :'Array<String>',
        'kms_key_id': :'String',
        'capacity_in_gbs': :'Integer',
        'subnet_id': :'String',
        'performance_tier': :'String',
        'management_service_address': :'String',
        'file_system_name': :'String',
        'lnet': :'String',
        'major_version': :'String',
        'cluster_placement_group_id': :'String',
        'time_billing_cycle_end': :'DateTime',
        'maintenance_window': :'OCI::LustreFileStorage::Models::MaintenanceWindow',
        'root_squash_configuration': :'OCI::LustreFileStorage::Models::RootSquashConfiguration'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :id The value to assign to the {#id} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [String] :availability_domain The value to assign to the {#availability_domain} property
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :file_system_description The value to assign to the {#file_system_description} property
    # @option attributes [DateTime] :time_created The value to assign to the {#time_created} property
    # @option attributes [DateTime] :time_updated The value to assign to the {#time_updated} property
    # @option attributes [String] :lifecycle_state The value to assign to the {#lifecycle_state} property
    # @option attributes [String] :lifecycle_details The value to assign to the {#lifecycle_details} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :system_tags The value to assign to the {#system_tags} property
    # @option attributes [Array<String>] :nsg_ids The value to assign to the {#nsg_ids} property
    # @option attributes [String] :kms_key_id The value to assign to the {#kms_key_id} property
    # @option attributes [Integer] :capacity_in_gbs The value to assign to the {#capacity_in_gbs} property
    # @option attributes [String] :subnet_id The value to assign to the {#subnet_id} property
    # @option attributes [String] :performance_tier The value to assign to the {#performance_tier} property
    # @option attributes [String] :management_service_address The value to assign to the {#management_service_address} property
    # @option attributes [String] :file_system_name The value to assign to the {#file_system_name} property
    # @option attributes [String] :lnet The value to assign to the {#lnet} property
    # @option attributes [String] :major_version The value to assign to the {#major_version} property
    # @option attributes [String] :cluster_placement_group_id The value to assign to the {#cluster_placement_group_id} property
    # @option attributes [DateTime] :time_billing_cycle_end The value to assign to the {#time_billing_cycle_end} property
    # @option attributes [OCI::LustreFileStorage::Models::MaintenanceWindow] :maintenance_window The value to assign to the {#maintenance_window} property
    # @option attributes [OCI::LustreFileStorage::Models::RootSquashConfiguration] :root_squash_configuration The value to assign to the {#root_squash_configuration} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.id = attributes[:'id'] if attributes[:'id']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.availability_domain = attributes[:'availabilityDomain'] if attributes[:'availabilityDomain']

      raise 'You cannot provide both :availabilityDomain and :availability_domain' if attributes.key?(:'availabilityDomain') && attributes.key?(:'availability_domain')

      self.availability_domain = attributes[:'availability_domain'] if attributes[:'availability_domain']

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.file_system_description = attributes[:'fileSystemDescription'] if attributes[:'fileSystemDescription']

      raise 'You cannot provide both :fileSystemDescription and :file_system_description' if attributes.key?(:'fileSystemDescription') && attributes.key?(:'file_system_description')

      self.file_system_description = attributes[:'file_system_description'] if attributes[:'file_system_description']

      self.time_created = attributes[:'timeCreated'] if attributes[:'timeCreated']

      raise 'You cannot provide both :timeCreated and :time_created' if attributes.key?(:'timeCreated') && attributes.key?(:'time_created')

      self.time_created = attributes[:'time_created'] if attributes[:'time_created']

      self.time_updated = attributes[:'timeUpdated'] if attributes[:'timeUpdated']

      raise 'You cannot provide both :timeUpdated and :time_updated' if attributes.key?(:'timeUpdated') && attributes.key?(:'time_updated')

      self.time_updated = attributes[:'time_updated'] if attributes[:'time_updated']

      self.lifecycle_state = attributes[:'lifecycleState'] if attributes[:'lifecycleState']

      raise 'You cannot provide both :lifecycleState and :lifecycle_state' if attributes.key?(:'lifecycleState') && attributes.key?(:'lifecycle_state')

      self.lifecycle_state = attributes[:'lifecycle_state'] if attributes[:'lifecycle_state']

      self.lifecycle_details = attributes[:'lifecycleDetails'] if attributes[:'lifecycleDetails']

      raise 'You cannot provide both :lifecycleDetails and :lifecycle_details' if attributes.key?(:'lifecycleDetails') && attributes.key?(:'lifecycle_details')

      self.lifecycle_details = attributes[:'lifecycle_details'] if attributes[:'lifecycle_details']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']

      self.system_tags = attributes[:'systemTags'] if attributes[:'systemTags']

      raise 'You cannot provide both :systemTags and :system_tags' if attributes.key?(:'systemTags') && attributes.key?(:'system_tags')

      self.system_tags = attributes[:'system_tags'] if attributes[:'system_tags']

      self.nsg_ids = attributes[:'nsgIds'] if attributes[:'nsgIds']

      raise 'You cannot provide both :nsgIds and :nsg_ids' if attributes.key?(:'nsgIds') && attributes.key?(:'nsg_ids')

      self.nsg_ids = attributes[:'nsg_ids'] if attributes[:'nsg_ids']

      self.kms_key_id = attributes[:'kmsKeyId'] if attributes[:'kmsKeyId']

      raise 'You cannot provide both :kmsKeyId and :kms_key_id' if attributes.key?(:'kmsKeyId') && attributes.key?(:'kms_key_id')

      self.kms_key_id = attributes[:'kms_key_id'] if attributes[:'kms_key_id']

      self.capacity_in_gbs = attributes[:'capacityInGBs'] if attributes[:'capacityInGBs']

      raise 'You cannot provide both :capacityInGBs and :capacity_in_gbs' if attributes.key?(:'capacityInGBs') && attributes.key?(:'capacity_in_gbs')

      self.capacity_in_gbs = attributes[:'capacity_in_gbs'] if attributes[:'capacity_in_gbs']

      self.subnet_id = attributes[:'subnetId'] if attributes[:'subnetId']

      raise 'You cannot provide both :subnetId and :subnet_id' if attributes.key?(:'subnetId') && attributes.key?(:'subnet_id')

      self.subnet_id = attributes[:'subnet_id'] if attributes[:'subnet_id']

      self.performance_tier = attributes[:'performanceTier'] if attributes[:'performanceTier']

      raise 'You cannot provide both :performanceTier and :performance_tier' if attributes.key?(:'performanceTier') && attributes.key?(:'performance_tier')

      self.performance_tier = attributes[:'performance_tier'] if attributes[:'performance_tier']

      self.management_service_address = attributes[:'managementServiceAddress'] if attributes[:'managementServiceAddress']

      raise 'You cannot provide both :managementServiceAddress and :management_service_address' if attributes.key?(:'managementServiceAddress') && attributes.key?(:'management_service_address')

      self.management_service_address = attributes[:'management_service_address'] if attributes[:'management_service_address']

      self.file_system_name = attributes[:'fileSystemName'] if attributes[:'fileSystemName']

      raise 'You cannot provide both :fileSystemName and :file_system_name' if attributes.key?(:'fileSystemName') && attributes.key?(:'file_system_name')

      self.file_system_name = attributes[:'file_system_name'] if attributes[:'file_system_name']

      self.lnet = attributes[:'lnet'] if attributes[:'lnet']

      self.major_version = attributes[:'majorVersion'] if attributes[:'majorVersion']

      raise 'You cannot provide both :majorVersion and :major_version' if attributes.key?(:'majorVersion') && attributes.key?(:'major_version')

      self.major_version = attributes[:'major_version'] if attributes[:'major_version']

      self.cluster_placement_group_id = attributes[:'clusterPlacementGroupId'] if attributes[:'clusterPlacementGroupId']

      raise 'You cannot provide both :clusterPlacementGroupId and :cluster_placement_group_id' if attributes.key?(:'clusterPlacementGroupId') && attributes.key?(:'cluster_placement_group_id')

      self.cluster_placement_group_id = attributes[:'cluster_placement_group_id'] if attributes[:'cluster_placement_group_id']

      self.time_billing_cycle_end = attributes[:'timeBillingCycleEnd'] if attributes[:'timeBillingCycleEnd']

      raise 'You cannot provide both :timeBillingCycleEnd and :time_billing_cycle_end' if attributes.key?(:'timeBillingCycleEnd') && attributes.key?(:'time_billing_cycle_end')

      self.time_billing_cycle_end = attributes[:'time_billing_cycle_end'] if attributes[:'time_billing_cycle_end']

      self.maintenance_window = attributes[:'maintenanceWindow'] if attributes[:'maintenanceWindow']

      raise 'You cannot provide both :maintenanceWindow and :maintenance_window' if attributes.key?(:'maintenanceWindow') && attributes.key?(:'maintenance_window')

      self.maintenance_window = attributes[:'maintenance_window'] if attributes[:'maintenance_window']

      self.root_squash_configuration = attributes[:'rootSquashConfiguration'] if attributes[:'rootSquashConfiguration']

      raise 'You cannot provide both :rootSquashConfiguration and :root_squash_configuration' if attributes.key?(:'rootSquashConfiguration') && attributes.key?(:'root_squash_configuration')

      self.root_squash_configuration = attributes[:'root_squash_configuration'] if attributes[:'root_squash_configuration']
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
    # @param [Object] performance_tier Object to be assigned
    def performance_tier=(performance_tier)
      # rubocop:disable Style/ConditionalAssignment
      if performance_tier && !PERFORMANCE_TIER_ENUM.include?(performance_tier)
        OCI.logger.debug("Unknown value for 'performance_tier' [" + performance_tier + "]. Mapping to 'PERFORMANCE_TIER_UNKNOWN_ENUM_VALUE'") if OCI.logger
        @performance_tier = PERFORMANCE_TIER_UNKNOWN_ENUM_VALUE
      else
        @performance_tier = performance_tier
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
        compartment_id == other.compartment_id &&
        availability_domain == other.availability_domain &&
        display_name == other.display_name &&
        file_system_description == other.file_system_description &&
        time_created == other.time_created &&
        time_updated == other.time_updated &&
        lifecycle_state == other.lifecycle_state &&
        lifecycle_details == other.lifecycle_details &&
        freeform_tags == other.freeform_tags &&
        defined_tags == other.defined_tags &&
        system_tags == other.system_tags &&
        nsg_ids == other.nsg_ids &&
        kms_key_id == other.kms_key_id &&
        capacity_in_gbs == other.capacity_in_gbs &&
        subnet_id == other.subnet_id &&
        performance_tier == other.performance_tier &&
        management_service_address == other.management_service_address &&
        file_system_name == other.file_system_name &&
        lnet == other.lnet &&
        major_version == other.major_version &&
        cluster_placement_group_id == other.cluster_placement_group_id &&
        time_billing_cycle_end == other.time_billing_cycle_end &&
        maintenance_window == other.maintenance_window &&
        root_squash_configuration == other.root_squash_configuration
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
      [id, compartment_id, availability_domain, display_name, file_system_description, time_created, time_updated, lifecycle_state, lifecycle_details, freeform_tags, defined_tags, system_tags, nsg_ids, kms_key_id, capacity_in_gbs, subnet_id, performance_tier, management_service_address, file_system_name, lnet, major_version, cluster_placement_group_id, time_billing_cycle_end, maintenance_window, root_squash_configuration].hash
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
