# dbag

Client library to fetch and manage data bags from a server with client side encryption. Databags can be used for settings, app configurations and arbitrary json data.

## Installation

    gem install dbag
    
## Usage

    require "lib/dbag";
    
    # Setup: Initial use, this will create a config file and create an encryption secret key
    Dbag::Client.setup(username, password)
    
    client = Dbag::Client.new("http://YOUR_ENDPOINT") # pass in the base url of your databags server

    data_bag = client.find("A DATABAG ID")
    data_bags = client.all

    client.to_file(data_bag, "/your/path/your_file.json")
    client.to_file(data_bag, "/your/path/your_file.yml", :yaml)

    new_data_bag = {"foo" => "bar", "baz" => "foo"}
    client.create(["index key 1"], new_data_bag)
    new_data_bag["foo"] = "bar2"
    client.update(new_data_bag)

    data_bag2 = client.from_file("NEW DATA BAG KEY 2", "/your/path/the_file_to_store.json")
    data_bag3 = client.from_file("NEW DATA BAG KEY 3", "/path/some.yml", :yaml)

## Contributing to dbag
 
* Check out the latest master to make sure the feature hasn't been implemented or the bug hasn't been fixed yet.
* Check out the issue tracker to make sure someone already hasn't requested it and/or contributed it.
* Fork the project.
* Start a feature/bugfix branch.
* Commit and push until you are happy with your contribution.
* Make sure to add tests for it. This is important so I don't break it in a future version unintentionally.
* Please try not to mess with the Rakefile, version, or history. If you want to have your own version, or is otherwise necessary, that is fine, but please isolate to its own commit so I can cherry-pick around it.

## Copyright

Copyright (c) 2012 Oliver Kiessler. See LICENSE.txt for further details.
