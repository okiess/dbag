module Dbag
  class Client
    include HTTParty
    attr_accessor :base_url, :auth_token, :logger, :log_level

    def initialize(base_url, auth_token)
      self.base_url = base_url
      self.auth_token = auth_token
      self.logger = Logger.new(STDOUT)
      self.logger.level = (self.log_level || Logger::DEBUG)
    end

    def all
      if (response = get_response(:get, '/data_bags.json')).response.is_a?(Net::HTTPOK)
        response.parsed_response
      end
    end

    def find(key, environment = 'production')
      if (response = get_response(:get, "/data_bags/#{key}.json", {:environment => environment})).response.is_a?(Net::HTTPOK)
        JSON.parse(response.parsed_response["bag_string"]) if response.parsed_response
      end
    end

    def create(key, environment, data_bag = {}, encrypted = false)
      raise "Invalid Databag!" unless key or data_bag
      response = get_response(:post, '/data_bags.json', 
        {:body => {:data_bag => {:key => key, :bag_string_clear => data_bag.to_json, 
         :encrypted => encrypted, :environment => (environment || 'production')}}})
    end

    def update(key, environment, data_bag = {}, encrypted = false)
      raise "Invalid Databag!" unless key or data_bag
      response = get_response(:put, "/data_bags/#{key}.json", 
        {:body => {:data_bag => {:bag_string_clear => data_bag.to_json, 
         :encrypted => encrypted}, :environment => (environment || 'production')}})
    end

    def to_file(hash, path, format = :json)      
      File.open(path, "w") do |f|
        if format == :json
          f.write(JSON.pretty_generate(hash))
        elsif format == :yaml
          f.write(hash.to_yaml)
        end
      end
    end

    def from_file(new_key, environment, path, encrypted = false, format = :json)
      File.open(path, "r" ) do |f|
        if format == :json
          if (json = JSON.load(f))
            create(new_key, environment, json, encrypted)
          end
        elsif format == :yaml
          if (yaml = YAML.load_file(path))
            create(new_key, environment, yaml, encrypted)
          end
        end
      end
    end

    private
    def get_response(http_verb, endpoint, options = {})
      begin
        endpoint_value = "#{self.base_url}#{URI.escape(endpoint)}?auth_token=#{self.auth_token}"
        logger.debug("Using endpoint: #{endpoint_value}")
        body = {}; body.merge!(options) if options and options.any?
        if http_verb == :post or http_verb == :put
          logger.debug("Body: #{body.inspect}")
          response = HTTParty.send(http_verb, endpoint_value, body)
        else
          if options and options.any? and options[:environment]
            endpoint_value = "#{endpoint_value}&environment=#{options[:environment]}"
          end
          response = HTTParty.send(http_verb, endpoint_value) 
        end
        logger.debug("Response: #{response.inspect}") if response
        response
      rescue => e
        logger.error("Could not connect to backend: #{e.message}")
      end
    end
  end
end
