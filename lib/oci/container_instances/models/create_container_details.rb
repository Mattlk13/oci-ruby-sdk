# Copyright (c) 2016, 2025, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

# NOTE: This class is auto generated by OracleSDKGenerator. DO NOT EDIT. API Version: 20210415
require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective, Metrics/LineLength
module OCI
  # Information to create a new container within a container instance.
  #
  # The container created by this call contains both the tags specified
  # in this object and any tags specified in the parent container instance.
  #
  # The container is created in the same compartment, availability domain,
  # and fault domain as its container instance.
  #
  class ContainerInstances::Models::CreateContainerDetails
    # A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
    # If you don't provide a name, a name is generated automatically.
    #
    # @return [String]
    attr_accessor :display_name

    # **[Required]** A URL identifying the image that the container runs in, such as docker.io/library/busybox:latest. If you do not provide a tag, the tag will default to latest.
    #
    # If no registry is provided, will default the registry to public docker hub `docker.io/library`.
    #
    # The registry used for container image must be reachable over the Container Instance's VNIC.
    #
    # @return [String]
    attr_accessor :image_url

    # An optional command that overrides the ENTRYPOINT process.
    # If you do not provide a value, the existing ENTRYPOINT process defined in the image is used.
    #
    # @return [Array<String>]
    attr_accessor :command

    # A list of string arguments for a container's ENTRYPOINT process.
    #
    # Many containers use an ENTRYPOINT process pointing to a shell
    # (/bin/bash). For those containers, this argument list
    # specifies the main command in the container process.
    #
    # The total size of all arguments combined must be 64 KB or smaller.
    #
    # @return [Array<String>]
    attr_accessor :arguments

    # The working directory within the container's filesystem for
    # the container process. If not specified, the default
    # working directory from the image is used.
    #
    # @return [String]
    attr_accessor :working_directory

    # A map of additional environment variables to set in the environment of the container's
    # ENTRYPOINT process. These variables are in addition to any variables already defined
    # in the container's image.
    #
    # The total size of all environment variables combined, name and values, must be 64 KB or smaller.
    #
    # @return [Hash<String, String>]
    attr_accessor :environment_variables

    # List of the volume mounts.
    #
    # @return [Array<OCI::ContainerInstances::Models::CreateVolumeMountDetails>]
    attr_accessor :volume_mounts

    # Determines if the container will have access to the container instance resource principal.
    #
    # This method utilizes resource principal version 2.2. For information on how to use the exposed resource principal elements, see
    # https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdk_authentication_methods.htm#sdk_authentication_methods_resource_principal.
    #
    # @return [BOOLEAN]
    attr_accessor :is_resource_principal_disabled

    # @return [OCI::ContainerInstances::Models::CreateContainerResourceConfigDetails]
    attr_accessor :resource_config

    # list of container health checks to check container status and take appropriate action if container status is failed.
    # There are two types of health checks that we currently support HTTP and TCP.
    #
    # @return [Array<OCI::ContainerInstances::Models::CreateContainerHealthCheckDetails>]
    attr_accessor :health_checks

    # @return [OCI::ContainerInstances::Models::CreateSecurityContextDetails]
    attr_accessor :security_context

    # Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
    # Example: `{\"bar-key\": \"value\"}`
    #
    # @return [Hash<String, String>]
    attr_accessor :freeform_tags

    # Defined tags for this resource. Each key is predefined and scoped to a namespace.
    # Example: `{\"foo-namespace\": {\"bar-key\": \"value\"}}`.
    #
    # @return [Hash<String, Hash<String, Object>>]
    attr_accessor :defined_tags

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'displayName',
        'image_url': :'imageUrl',
        'command': :'command',
        'arguments': :'arguments',
        'working_directory': :'workingDirectory',
        'environment_variables': :'environmentVariables',
        'volume_mounts': :'volumeMounts',
        'is_resource_principal_disabled': :'isResourcePrincipalDisabled',
        'resource_config': :'resourceConfig',
        'health_checks': :'healthChecks',
        'security_context': :'securityContext',
        'freeform_tags': :'freeformTags',
        'defined_tags': :'definedTags'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'display_name': :'String',
        'image_url': :'String',
        'command': :'Array<String>',
        'arguments': :'Array<String>',
        'working_directory': :'String',
        'environment_variables': :'Hash<String, String>',
        'volume_mounts': :'Array<OCI::ContainerInstances::Models::CreateVolumeMountDetails>',
        'is_resource_principal_disabled': :'BOOLEAN',
        'resource_config': :'OCI::ContainerInstances::Models::CreateContainerResourceConfigDetails',
        'health_checks': :'Array<OCI::ContainerInstances::Models::CreateContainerHealthCheckDetails>',
        'security_context': :'OCI::ContainerInstances::Models::CreateSecurityContextDetails',
        'freeform_tags': :'Hash<String, String>',
        'defined_tags': :'Hash<String, Hash<String, Object>>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :display_name The value to assign to the {#display_name} property
    # @option attributes [String] :image_url The value to assign to the {#image_url} property
    # @option attributes [Array<String>] :command The value to assign to the {#command} property
    # @option attributes [Array<String>] :arguments The value to assign to the {#arguments} property
    # @option attributes [String] :working_directory The value to assign to the {#working_directory} property
    # @option attributes [Hash<String, String>] :environment_variables The value to assign to the {#environment_variables} property
    # @option attributes [Array<OCI::ContainerInstances::Models::CreateVolumeMountDetails>] :volume_mounts The value to assign to the {#volume_mounts} property
    # @option attributes [BOOLEAN] :is_resource_principal_disabled The value to assign to the {#is_resource_principal_disabled} property
    # @option attributes [OCI::ContainerInstances::Models::CreateContainerResourceConfigDetails] :resource_config The value to assign to the {#resource_config} property
    # @option attributes [Array<OCI::ContainerInstances::Models::CreateContainerHealthCheckDetails>] :health_checks The value to assign to the {#health_checks} property
    # @option attributes [OCI::ContainerInstances::Models::CreateSecurityContextDetails] :security_context The value to assign to the {#security_context} property
    # @option attributes [Hash<String, String>] :freeform_tags The value to assign to the {#freeform_tags} property
    # @option attributes [Hash<String, Hash<String, Object>>] :defined_tags The value to assign to the {#defined_tags} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.display_name = attributes[:'displayName'] if attributes[:'displayName']

      raise 'You cannot provide both :displayName and :display_name' if attributes.key?(:'displayName') && attributes.key?(:'display_name')

      self.display_name = attributes[:'display_name'] if attributes[:'display_name']

      self.image_url = attributes[:'imageUrl'] if attributes[:'imageUrl']

      raise 'You cannot provide both :imageUrl and :image_url' if attributes.key?(:'imageUrl') && attributes.key?(:'image_url')

      self.image_url = attributes[:'image_url'] if attributes[:'image_url']

      self.command = attributes[:'command'] if attributes[:'command']

      self.arguments = attributes[:'arguments'] if attributes[:'arguments']

      self.working_directory = attributes[:'workingDirectory'] if attributes[:'workingDirectory']
      self.working_directory = "null" if working_directory.nil? && !attributes.key?(:'workingDirectory') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :workingDirectory and :working_directory' if attributes.key?(:'workingDirectory') && attributes.key?(:'working_directory')

      self.working_directory = attributes[:'working_directory'] if attributes[:'working_directory']
      self.working_directory = "null" if working_directory.nil? && !attributes.key?(:'workingDirectory') && !attributes.key?(:'working_directory') # rubocop:disable Style/StringLiterals

      self.environment_variables = attributes[:'environmentVariables'] if attributes[:'environmentVariables']

      raise 'You cannot provide both :environmentVariables and :environment_variables' if attributes.key?(:'environmentVariables') && attributes.key?(:'environment_variables')

      self.environment_variables = attributes[:'environment_variables'] if attributes[:'environment_variables']

      self.volume_mounts = attributes[:'volumeMounts'] if attributes[:'volumeMounts']

      raise 'You cannot provide both :volumeMounts and :volume_mounts' if attributes.key?(:'volumeMounts') && attributes.key?(:'volume_mounts')

      self.volume_mounts = attributes[:'volume_mounts'] if attributes[:'volume_mounts']

      self.is_resource_principal_disabled = attributes[:'isResourcePrincipalDisabled'] unless attributes[:'isResourcePrincipalDisabled'].nil?
      self.is_resource_principal_disabled = false if is_resource_principal_disabled.nil? && !attributes.key?(:'isResourcePrincipalDisabled') # rubocop:disable Style/StringLiterals

      raise 'You cannot provide both :isResourcePrincipalDisabled and :is_resource_principal_disabled' if attributes.key?(:'isResourcePrincipalDisabled') && attributes.key?(:'is_resource_principal_disabled')

      self.is_resource_principal_disabled = attributes[:'is_resource_principal_disabled'] unless attributes[:'is_resource_principal_disabled'].nil?
      self.is_resource_principal_disabled = false if is_resource_principal_disabled.nil? && !attributes.key?(:'isResourcePrincipalDisabled') && !attributes.key?(:'is_resource_principal_disabled') # rubocop:disable Style/StringLiterals

      self.resource_config = attributes[:'resourceConfig'] if attributes[:'resourceConfig']

      raise 'You cannot provide both :resourceConfig and :resource_config' if attributes.key?(:'resourceConfig') && attributes.key?(:'resource_config')

      self.resource_config = attributes[:'resource_config'] if attributes[:'resource_config']

      self.health_checks = attributes[:'healthChecks'] if attributes[:'healthChecks']

      raise 'You cannot provide both :healthChecks and :health_checks' if attributes.key?(:'healthChecks') && attributes.key?(:'health_checks')

      self.health_checks = attributes[:'health_checks'] if attributes[:'health_checks']

      self.security_context = attributes[:'securityContext'] if attributes[:'securityContext']

      raise 'You cannot provide both :securityContext and :security_context' if attributes.key?(:'securityContext') && attributes.key?(:'security_context')

      self.security_context = attributes[:'security_context'] if attributes[:'security_context']

      self.freeform_tags = attributes[:'freeformTags'] if attributes[:'freeformTags']

      raise 'You cannot provide both :freeformTags and :freeform_tags' if attributes.key?(:'freeformTags') && attributes.key?(:'freeform_tags')

      self.freeform_tags = attributes[:'freeform_tags'] if attributes[:'freeform_tags']

      self.defined_tags = attributes[:'definedTags'] if attributes[:'definedTags']

      raise 'You cannot provide both :definedTags and :defined_tags' if attributes.key?(:'definedTags') && attributes.key?(:'defined_tags')

      self.defined_tags = attributes[:'defined_tags'] if attributes[:'defined_tags']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        display_name == other.display_name &&
        image_url == other.image_url &&
        command == other.command &&
        arguments == other.arguments &&
        working_directory == other.working_directory &&
        environment_variables == other.environment_variables &&
        volume_mounts == other.volume_mounts &&
        is_resource_principal_disabled == other.is_resource_principal_disabled &&
        resource_config == other.resource_config &&
        health_checks == other.health_checks &&
        security_context == other.security_context &&
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
      [display_name, image_url, command, arguments, working_directory, environment_variables, volume_mounts, is_resource_principal_disabled, resource_config, health_checks, security_context, freeform_tags, defined_tags].hash
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
