# Copyright (c) 2016, 2019, Oracle and/or its affiliates. All rights reserved.

require 'date'

# rubocop:disable Lint/UnneededCopDisableDirective
module OCI
  # The set of aggregated data returned for a metric.
  # For information about metrics, see [Metrics Overview](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#MetricsOverview).
  #
  class Monitoring::Models::MetricData # rubocop:disable Metrics/LineLength
    # **[Required]** The reference provided in a metric definition to indicate the source service or
    # application that emitted the metric.
    #
    # Example: `oci_computeagent`
    #
    # @return [String]
    attr_accessor :namespace

    # **[Required]** The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the
    # resources from which the aggregated data was returned.
    #
    # @return [String]
    attr_accessor :compartment_id

    # **[Required]** The name of the metric.
    #
    # Example: `CpuUtilization`
    #
    # @return [String]
    attr_accessor :name

    # **[Required]** Qualifiers provided in the definition of the returned metric.
    # Available dimensions vary by metric namespace. Each dimension takes the form of a key-value pair.
    #
    # Example: `\"resourceId\": \"ocid1.instance.region1.phx.exampleuniqueID\"`
    #
    # @return [Hash<String, String>]
    attr_accessor :dimensions

    # The references provided in a metric definition to indicate extra information about the metric.
    #
    # Example: `\"unit\": \"bytes\"`
    #
    # @return [Hash<String, String>]
    attr_accessor :metadata

    # The time between calculated aggregation windows. Use with the query interval to vary the
    # frequency at which aggregated data points are returned. For example, use a query interval of
    # 5 minutes with a resolution of 1 minute to retrieve five-minute aggregations at a one-minute
    # frequency. The resolution must be equal or less than the interval in the query. The default
    # resolution is 1m (one minute). Supported values: `1m`-`60m` (also `1h`).
    #
    # Example: `5m`
    #
    # @return [String]
    attr_accessor :resolution

    # **[Required]** The list of timestamp-value pairs returned for the specified request. Metric values are rolled up to the start time specified in the request.
    #
    # @return [Array<OCI::Monitoring::Models::AggregatedDatapoint>]
    attr_accessor :aggregated_datapoints

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        # rubocop:disable Style/SymbolLiteral
        'namespace': :'namespace',
        'compartment_id': :'compartmentId',
        'name': :'name',
        'dimensions': :'dimensions',
        'metadata': :'metadata',
        'resolution': :'resolution',
        'aggregated_datapoints': :'aggregatedDatapoints'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # Attribute type mapping.
    def self.swagger_types
      {
        # rubocop:disable Style/SymbolLiteral
        'namespace': :'String',
        'compartment_id': :'String',
        'name': :'String',
        'dimensions': :'Hash<String, String>',
        'metadata': :'Hash<String, String>',
        'resolution': :'String',
        'aggregated_datapoints': :'Array<OCI::Monitoring::Models::AggregatedDatapoint>'
        # rubocop:enable Style/SymbolLiteral
      }
    end

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:disable Metrics/LineLength, Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral


    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    # @option attributes [String] :namespace The value to assign to the {#namespace} property
    # @option attributes [String] :compartment_id The value to assign to the {#compartment_id} property
    # @option attributes [String] :name The value to assign to the {#name} property
    # @option attributes [Hash<String, String>] :dimensions The value to assign to the {#dimensions} property
    # @option attributes [Hash<String, String>] :metadata The value to assign to the {#metadata} property
    # @option attributes [String] :resolution The value to assign to the {#resolution} property
    # @option attributes [Array<OCI::Monitoring::Models::AggregatedDatapoint>] :aggregated_datapoints The value to assign to the {#aggregated_datapoints} property
    def initialize(attributes = {})
      return unless attributes.is_a?(Hash)

      # convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

      self.namespace = attributes[:'namespace'] if attributes[:'namespace']

      self.compartment_id = attributes[:'compartmentId'] if attributes[:'compartmentId']

      raise 'You cannot provide both :compartmentId and :compartment_id' if attributes.key?(:'compartmentId') && attributes.key?(:'compartment_id')

      self.compartment_id = attributes[:'compartment_id'] if attributes[:'compartment_id']

      self.name = attributes[:'name'] if attributes[:'name']

      self.dimensions = attributes[:'dimensions'] if attributes[:'dimensions']

      self.metadata = attributes[:'metadata'] if attributes[:'metadata']

      self.resolution = attributes[:'resolution'] if attributes[:'resolution']

      self.aggregated_datapoints = attributes[:'aggregatedDatapoints'] if attributes[:'aggregatedDatapoints']

      raise 'You cannot provide both :aggregatedDatapoints and :aggregated_datapoints' if attributes.key?(:'aggregatedDatapoints') && attributes.key?(:'aggregated_datapoints')

      self.aggregated_datapoints = attributes[:'aggregated_datapoints'] if attributes[:'aggregated_datapoints']
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity
    # rubocop:enable Metrics/LineLength, Metrics/MethodLength, Layout/EmptyLines, Style/SymbolLiteral

    # rubocop:disable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Metrics/LineLength, Layout/EmptyLines


    # Checks equality by comparing each attribute.
    # @param [Object] other the other object to be compared
    def ==(other)
      return true if equal?(other)

      self.class == other.class &&
        namespace == other.namespace &&
        compartment_id == other.compartment_id &&
        name == other.name &&
        dimensions == other.dimensions &&
        metadata == other.metadata &&
        resolution == other.resolution &&
        aggregated_datapoints == other.aggregated_datapoints
    end
    # rubocop:enable Metrics/CyclomaticComplexity, Metrics/AbcSize, Metrics/PerceivedComplexity, Metrics/LineLength, Layout/EmptyLines

    # @see the `==` method
    # @param [Object] other the other object to be compared
    def eql?(other)
      self == other
    end

    # rubocop:disable Metrics/AbcSize, Metrics/LineLength, Layout/EmptyLines


    # Calculates hash code according to all attributes.
    # @return [Fixnum] Hash code
    def hash
      [namespace, compartment_id, name, dimensions, metadata, resolution, aggregated_datapoints].hash
    end
    # rubocop:enable Metrics/AbcSize, Metrics/LineLength, Layout/EmptyLines

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
# rubocop:enable Lint/UnneededCopDisableDirective