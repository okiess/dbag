# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "dbag"
  s.version = "0.0.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Oliver Kiessler"]
  s.description = "Client library to fetch and manage data bags from a server. Databags can be used for settings, app configurations and arbitrary json data."
  s.email = "kiessler@inceedo.com"
  s.extra_rdoc_files = [
    "LICENSE.txt",
    "README.md"
  ]
  s.files = [
    ".document",
    "Gemfile",
    "LICENSE.txt",
    "README.md",
    "Rakefile",
    "VERSION",
    "lib/dbag.rb",
    "lib/dbag/client.rb",
    "test/helper.rb",
    "test/test_dbag.rb"
  ]
  s.homepage = "http://github.com/okiess/dbag"
  s.licenses = ["MIT"]
  s.summary = "Client for a Data Bag server"

  s.add_runtime_dependency "httparty", ">= 0.21.0"
  s.add_runtime_dependency "multi_json"
  s.add_runtime_dependency "encryptor", ">= 1.1.3"
  s.add_runtime_dependency "sqlite3", ">= 2.9.5"

  s.add_development_dependency "shoulda"
  s.add_development_dependency "bundler", ">= 2.0"
  s.add_development_dependency "rake", ">= 12.3.3"
  s.add_development_dependency "git", ">= 1.11.0"
  s.add_development_dependency "test-unit", "~> 3.7"
end
