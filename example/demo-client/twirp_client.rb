require 'rack'

require_relative '../app/controllers/rpc/hello_world/service_twirp.rb'
require_relative '../../lib/middleware/egress/aws_faraday_connection'

addr = "http://ec2-13-127-156-48.ap-south-1.compute.amazonaws.com:8000/twirp"

conn = BuildSecurity::Egress::AwsFaradayConnection.new(addr)

# Assume hello_world_server is running locally
twirp_client = Example::HelloWorld::HelloWorldClient.new(conn)

resp = twirp_client.hello(name: "World")
if resp.error
  puts "Error during Twirp request"
else
  puts "Successfully connected: #{resp.data.message}"
end
