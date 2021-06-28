require 'rack'

require_relative '../controllers/rpc/hello_world/service_twirp.rb'
require_relative '../../../lib/middleware/egress/inter_instance_connection'

addr = "http://localhost:3000/twirp"
conn = Middleware::Egress::AwsInterInstanceConnection.new(addr)

# Assume hello_world_server is running locally
c = Example::HelloWorld::HelloWorldClient.new(addr)

resp = c.hello(name: "World")
if resp.error
  puts resp.error
else
  puts resp.data.message
end
