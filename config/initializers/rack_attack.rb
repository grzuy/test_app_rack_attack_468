# require 'prometheus_exporter/client'

class Rack::Attack

  # if Rails.env.staging? || Rails.env.production?
    # redis_url_with_auth = ENV['REDIS_URL'].sub "redis://", "rediss://user:#{ENV['REDIS_AUTH']}@"
    # Rack::Attack.cache.store = ActiveSupport::Cache::RedisStore.new(redis_url_with_auth, { expires_in: 90.minutes })
    Rack::Attack.cache.store = ActiveSupport::Cache::RedisStore.new(expires_in: 90.minutes)
  # end

  # client = PrometheusExporter::Client.default
  # gauge = client.register(:gauge , "sauron.rackattack.req_per_ip", "blocked by ip")

  limit =  Rails.configuration.ratelimit["requests"] || 0
  period =  Rails.configuration.ratelimit["period"] || 1
  internal_limit =  Rails.configuration.ratelimit["internal_requests"] || limit
  internal_period =  Rails.configuration.ratelimit["internal_period"] || period
  internal_path = "/internal"

  # Excludes internal routes
  Rack::Attack.track("req_per_ip_external", limit: limit, period: period.seconds) do |req|
    distinguisher = "#{req.ip}, #{req.request_method}, #{req.path}"
    distinguisher unless req.path.start_with?(internal_path)
  end

  # Only internal routes
  Rack::Attack.track("req_per_ip_internal", limit: internal_limit, period: internal_period.seconds) do |req|
    distinguisher = "#{req.ip}, #{req.request_method}, #{req.path}"
    distinguisher if req.path.start_with?(internal_path)
  end

  # Track it using ActiveSupport::Notification
  ActiveSupport::Notifications.subscribe(/rack_attack/) do |name, start, finish, request_id, payload|
    req = payload[:request]
    attack = req.env['rack.attack.matched']
    Rails.logger.warn(event: "rack_attack_triggered", attack_type: attack, ip: req.ip, method: req.request_method, path: req.path)
    if Rails.env.production? || Rails.env.staging?
      # gauge.observe(1)
    end
  end
end
