# frozen_string_literal: true

# Be sure to restart your server when you modify this file.

# Define an application-wide content security policy.
# See the Securing Rails Applications Guide for more information:
# https://guides.rubyonrails.org/security.html#content-security-policy-header

Rails.application.configure do
  # OpenGeofiction: the tile hosts are whatever config/layers.yml names, not
  # upstream's literal list of OpenStreetMap servers
  tile_hosts = YAML.load_file(Rails.root.join("config/layers.yml"))
                   .filter_map { |layer| layer["tileUrl"]&.sub("{s}", "a")&.[](%r{\Ahttps?://([^/]+)}, 1) }
                   .uniq

  connect_src = [:self, *tile_hosts]
  img_src = [:self, :data, "www.gravatar.com", *tile_hosts]
  script_src = [:self]

  connect_src << Settings.matomo["location"] if defined?(Settings.matomo)
  img_src << Settings.matomo["location"] if defined?(Settings.matomo)
  script_src << Settings.matomo["location"] if defined?(Settings.matomo)

  img_src << Settings.avatar_storage_url if Settings.key?(:avatar_storage_url)
  img_src << Settings.trace_image_storage_url if Settings.key?(:trace_image_storage_url)

  config.content_security_policy do |policy|
    policy.default_src :self
    policy.child_src(:self)
    policy.connect_src(*connect_src)
    policy.font_src(:self)
    policy.form_action(:self)
    policy.frame_ancestors(:self)
    policy.frame_src(:self)
    policy.img_src(*img_src)
    policy.manifest_src(:self)
    policy.media_src(:none)
    policy.object_src(:none)
    policy.plugin_types
    policy.script_src(*script_src)
    policy.style_src(:self)
    policy.worker_src(:blob)
    policy.manifest_src(:self)
    policy.report_uri(Settings.csp_report_url) if Settings.key?(:csp_report_url)
  end

  # Generate session nonces for permitted importmap, inline scripts, and inline styles.
  config.content_security_policy_nonce_generator = ->(_request) { SecureRandom.base64(24) }
  config.content_security_policy_nonce_directives = %w[script-src style-src]

  # Report violations without enforcing the policy.
  config.content_security_policy_report_only = true unless Settings.csp_enforce
end
