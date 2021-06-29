Twirp::Rails.configuration do |c|
    # Modify the path below if you locates handlers under the different directory.
    c.handlers_path = Rails.root.join('app', 'controllers')
  end