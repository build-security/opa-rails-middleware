require 'rack'
require 'webrick'

require_relative 'hello_world/service_twirp.rb'

# Service implementation
class HelloWorldHandler
  include Twirp::Rails::Helpers
  bind Example::HelloWorld::HelloWorldService

  def hello(req, env)
    puts ">> Hello #{req.name}"
    {message: "Hello #{req.name}"}
  end
end
