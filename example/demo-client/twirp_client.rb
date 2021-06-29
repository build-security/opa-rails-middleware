require 'rack'

require_relative '../app/controllers/rpc/hello_world/service_twirp.rb'
require_relative '../../lib/middleware/egress/inter_instance_connection'

addr = "http://ec2-13-127-156-48.ap-south-1.compute.amazonaws.com:8000/twirp"
conn = Middleware::Egress::AwsInterInstanceConnection.new(addr)

# Assume hello_world_server is running locally
c = Example::HelloWorld::HelloWorldClient.new(conn)

resp = c.hello(name: "World")
if resp.error
  puts resp.error
else
  puts resp.data.message
end
