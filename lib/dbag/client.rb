module Dbag
  class Client
    include HTTParty
    attr_accessor :base_url, :api_version, :auth_token, :auth_token_valid_until, :logger, :log_level
    attr_accessor :username, :password

    def initialize(base_url = 'http://databags.io')
      self.api_version = 'v1'
      self.base_url = base_url
      self.logger = Logger.new(STDOUT)
      self.logger.level = (self.log_level || Logger::DEBUG)
    end

    def all(page = 1, decrypt = true, options = {})
      url_options = {}
      url_options[:page] = page
      url_options[:keys] = options[:keys] if options[:keys]
      response = get_response(:get, "/api/#{self.api_version}/data_bags.json", url_options)
      if response and response.parsed_response and response.code == 200
        if decrypt
          decrypted = []
          response.parsed_response.each do |item|
            item['json'] = JSON.parse(decrypt(item['json']))
            decrypted << item
          end
          return decrypted
        else
          return response.parsed_response
        end
      end
      nil
    end

    def query(keys, page = 1, decrypt = true)
      all(page, decrypt, { :keys => (keys.is_a?(String) ? [keys] : keys)})
    end

    def count
      response = get_response(:get, "/api/#{self.api_version}/data_bags/count.json")
      if response and response.parsed_response and response.code == 200
        return response.parsed_response['count']
      end
      nil
    end

    def dump(path = '/tmp', encrypted = true)
      if (data_bags = all(nil, false))
        data_bags.each do |data_bag|
          File.open("#{path}/#{data_bag['id']}#{encrypted ? '' : '.json'}", "w") do |f|
            f.write(encrypted ? data_bag['json'] : JSON.pretty_generate(JSON.parse(decrypt(data_bag['json']))))
          end
        end
      end
    end

    def find(data_bag_id)
      if (response = get_response(:get, "/api/#{self.api_version}/data_bags/#{data_bag_id}.json"))
        if (data_bag = response.parsed_response)
          data_bag['json'] = JSON.parse(decrypt(data_bag['json']))
          return data_bag
        end
      end
      nil
    end

    def create(keys = [], data_bag = {})
      raise "Invalid Databag!" unless data_bag.keys.any?
      response = get_response(:post, "/api/#{self.api_version}/data_bags.json", 
        {:body => {:data_bag => {:keys => (keys.is_a?(String) ? [keys] : keys), :json => encrypt(data_bag.to_json)}}})
    end

    def update(data_bag)
      raise "Invalid Databag!" unless data_bag
      data_bag['json'] = encrypt(data_bag['json'].to_json)
      data_bag.delete('url')
      response = get_response(:put, "/api/#{self.api_version}/data_bags/#{data_bag['id']}.json", {:body => {:data_bag => data_bag}})
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

    def from_file(path, keys = [], format = :json)
      File.open(path, "r" ) do |f|
        if format == :json
          if (json = JSON.load(f))
            create(keys, json)
          end
        elsif format == :yaml
          if (yaml = YAML.load_file(path))
            create(keys, yaml)
          end
        end
      end
    end

    def self.setup(email, password)
      raise ".dbag file exists!" if File.exists?("#{ENV['HOME']}/.dbag")
      File.open("#{ENV['HOME']}/.dbag", "w") do |f|
        hash = {
          :username => email,
          :salt => "#{Time.now.to_i}#{SecureRandom.hex(128)}",
          :secret_key => SecureRandom.hex(256),
          :iv => OpenSSL::Cipher::Cipher.new('aes-256-cbc').random_iv
        }
        # TODO: should the password really be saved to a file even if it is encrypted?
        encrypted_password = Encryptor.encrypt(password, :key => hash[:secret_key], :iv => hash[:iv],
          :salt => hash[:salt])
        hash[:password] = encrypted_password
        f.write(JSON.pretty_generate(hash))
      end
    end

    private
    def encrypt(data_bag_json_string)
      init_encryptor
      data_bag_json_string.encrypt
    end
    
    def decrypt(data_bag_json_string)
      init_encryptor
      data_bag_json_string.decrypt
    end
    
    def init_encryptor
      unless @secret_key
        raise "dbag file doesn't exist!" unless File.exists?("#{ENV['HOME']}/.dbag")
        File.open("#{ENV['HOME']}/.dbag", "r") do |f|
          if (json = JSON.load(f))
            @salt = json['salt']
            @secret_key = json['secret_key']
            @iv = json['iv']
            @username = json['username']
            @password = Encryptor.decrypt(json['password'], :key => @secret_key, :iv => @iv, :salt => @salt)
          end
        end
      end
      Encryptor.default_options.merge!(:key => @secret_key, :iv => @iv, :salt => @salt)
    end
  
    def get_response(http_verb, endpoint, options = {})
      response = nil
      get_auth_token if self.auth_token.nil? or (not self.auth_token_valid_until.nil? and self.auth_token_valid_until < DateTime.now)
      return nil unless self.auth_token
      begin
        endpoint_value = "#{self.base_url}#{URI.escape(endpoint)}?auth_token=#{self.auth_token}"
        logger.debug("Using endpoint: #{endpoint_value}")
        body = {}; body.merge!(options) if options and options.any?
        if http_verb == :post or http_verb == :put
          logger.debug("Body: #{body.inspect}")
          response = HTTParty.send(http_verb, endpoint_value, body)
        else
          endpoint_value = "#{endpoint_value}&page=#{options[:page]}" if options[:page]
          endpoint_value = "#{endpoint_value}&keys=#{URI.escape(options[:keys].join(' '))}" if options[:keys]
          response = HTTParty.send(http_verb, endpoint_value) 
        end
        if response
          logger.debug("Response: #{response.inspect}")
          if response.code == 401
            self.auth_token = nil
            self.auth_token_valid_until = nil
            return get_response(http_verb, endpoint, options) # retry
          end
        end
      rescue => e
        logger.error("Could not connect to backend: #{e.message}")
      end
      response
    end
    
    def get_auth_token
      init_encryptor unless self.username
      auth = {:username => self.username, :password => self.password}
      endpoint_value = "#{self.base_url}/api/#{self.api_version}/auth_tokens.json"
      body = {}
      options = { :body => {}, :basic_auth => auth }
      if (response = HTTParty.post(endpoint_value, options))
        if response.code == 401
          raise "Auth failed, auth token couldn't be created!"
        end
        if response.parsed_response and response.parsed_response['authentication_token']
          self.auth_token = response.parsed_response['authentication_token']
        end
        if response.parsed_response and response.parsed_response['authentication_token_valid_until']
          self.auth_token_valid_until = DateTime.parse(response.parsed_response['authentication_token_valid_until'].to_s)
        end
      end
    end
  end
end
