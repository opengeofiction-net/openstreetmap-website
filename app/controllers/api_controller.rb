# frozen_string_literal: true

class ApiController < ApplicationController
  skip_before_action :verify_authenticity_token

  before_action :check_api_readable

  around_action :api_call_handle_error, :api_call_timeout

  private

  ##
  # Set allowed request formats if no explicit format has been
  # requested via a URL suffix. Allowed formats are taken from
  # any HTTP Accept header with XML as the default.
  def set_request_formats
    unless params[:format]
      accept_header = request.headers["HTTP_ACCEPT"]

      if accept_header
        # Some clients (such asJOSM) send Accept headers which cannot be
        # parse by Rails, for example:
        #
        #   Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
        #
        # where both "*" and ".2" as a quality do not adhere to the syntax
        # described in RFC 7231, section 5.3.1, etc.
        #
        # As a workaround, and for back compatibility, default to XML format.
        mimetypes = begin
          Mime::Type.parse(accept_header)
        rescue Mime::Type::InvalidMimeType
          Array(Mime[:xml])
        end

        # Allow XML and JSON formats, and treat an all formats wildcard
        # as XML for backwards compatibility - all other formats are discarded
        # which will result in a 406 Not Acceptable response being sent
        formats = mimetypes.map do |mime|
          if mime.symbol == :xml || mime == "*/*" then :xml
          elsif mime.symbol == :json then :json
          end
        end
      else
        # Default to XML if no accept header was sent - this includes
        # the unit tests which don't set one by default
        formats = Array(:xml)
      end

      request.formats = formats.compact
    end
  end

  def authorize(errormessage: "Couldn't authenticate you", skip_blocks: false, skip_terms: false)
    # make the current_user object from any auth sources we have
    setup_user_auth(:skip_blocks => skip_blocks, :skip_terms => skip_terms)

    # error if we could not authenticate the user
    unless current_user
      basic_auth_challenge
      render :plain => errormessage, :status => :unauthorized
    end
  end

  def current_ability
    # Use capabilities from the oauth token if it exists and is a valid access token
    if doorkeeper_token&.accessible?
      user = User.find(doorkeeper_token.resource_owner_id)
      ApiAbility.new(user, expand_scopes(doorkeeper_token.scopes))
    elsif basic_auth_user
      # a password grants everything a token could, as it did before OAuth 2 became the only way in
      ApiAbility.new(basic_auth_user, expand_scopes(Oauth::SCOPES))
    else
      ApiAbility.new(nil, Set.new)
    end
  end

  def deny_access(_exception)
    if doorkeeper_token
      set_locale
      report_error t("oauth.permissions.missing"), :forbidden
    else
      basic_auth_challenge
      head :unauthorized
    end
  end

  ##
  # OpenGeofiction: HTTP basic authentication, for JOSM releases that cannot yet
  # authorise against a non-openstreetmap.org OAuth 2 server. Interim - gated on
  # basic_auth_support in settings.local.yml, off by default. A password is
  # checked exactly as the login form checks it (User#password_matches?,
  # which also upgrades old hash formats), and grants the full scope set.
  def basic_auth_user
    return @basic_auth_user if defined? @basic_auth_user
    return @basic_auth_user = nil unless Settings.basic_auth_support

    @basic_auth_user = authenticate_with_http_basic do |username, password|
      user = User.lookup(username) if username.present?
      user if user&.active? && password.present? && user.password_matches?(password)
    end
    logger.info "Authenticated as user #{@basic_auth_user.id} using basic authentication" if @basic_auth_user
    @basic_auth_user
  end

  ##
  # tell a client that sent no credentials that a password will do
  def basic_auth_challenge
    response.headers["WWW-Authenticate"] = "Basic realm=\"#{Settings.server_url}\"" if Settings.basic_auth_support
  end

  def expand_scopes(scopes)
    scopes = Set.new scopes
    if scopes.include?("write_api")
      scopes.add("write_map")
      scopes.add("write_changeset_comments")
      scopes.delete("write_api")
    end
    scopes
  end

  def gpx_status
    status = database_status
    status = "offline" if status == "online" && Settings.status == "gpx_offline"
    status
  end

  ##
  # sets up the current_user for use by other methods. this is mostly called
  # from the authorize method, but can be called elsewhere if authorisation
  # is optional.
  def setup_user_auth(skip_blocks: false, skip_terms: false)
    logger.info " setup_user_auth"
    # try and setup using OAuth, then (OpenGeofiction, interim) a password
    self.current_user = if doorkeeper_token&.accessible?
                          User.find(doorkeeper_token.resource_owner_id)
                        else
                          basic_auth_user
                        end

    # have we identified the user?
    if current_user
      # check if the user has been banned
      unless skip_blocks
        user_block = current_user.blocks.active.take
        unless user_block.nil?
          set_locale
          if user_block.zero_hour?
            report_error t("application.setup_user_auth.blocked_zero_hour"), :forbidden
          else
            report_error t("application.setup_user_auth.blocked"), :forbidden
          end
        end
      end

      # if the user hasn't seen the contributor terms then don't
      # allow editing - they have to go to the web site and see
      # (but can decline) the CTs to continue.
      if !current_user.terms_seen && !skip_terms
        set_locale
        report_error t("application.setup_user_auth.need_to_see_terms"), :forbidden
      end
    end
  end

  def api_call_handle_error
    yield
  rescue ActionController::UnknownFormat
    head :not_acceptable
  rescue ActiveRecord::RecordNotFound => e
    head :not_found
  rescue LibXML::XML::Error, ArgumentError => e
    report_error e.message, :bad_request
  rescue ActiveRecord::RecordInvalid => e
    message = "#{e.record.class} #{e.record.id}: "
    e.record.errors.each { |error| message << "#{error.attribute}: #{error.message} (#{e.record[error.attribute].inspect})" }
    report_error message, :bad_request
  rescue OSM::APIError => e
    report_error e.message, e.status
  rescue AbstractController::ActionNotFound, CanCan::AccessDenied => e
    raise
  rescue StandardError => e
    logger.info("API threw unexpected #{e.class} exception: #{e.message}")
    e.backtrace.each { |l| logger.info(l) }
    report_error "#{e.class}: #{e.message}", :internal_server_error
  end

  ##
  # wrap an api call in a timeout
  def api_call_timeout(&)
    Timeout.timeout(Settings.api_timeout, &)
  rescue ActionView::Template::Error => e
    e = e.cause

    if e.is_a?(Timeout::Error) ||
       (e.is_a?(ActiveRecord::StatementInvalid) && e.message.include?("execution expired"))
      ActiveRecord::Base.connection.raw_connection.cancel
      raise OSM::APITimeoutError
    else
      raise
    end
  rescue Timeout::Error
    ActiveRecord::Base.connection.raw_connection.cancel
    raise OSM::APITimeoutError
  end

  ##
  # check the api change rate limit
  def check_rate_limit(new_changes = 1)
    max_changes = ActiveRecord::Base.connection.select_value(
      "SELECT api_rate_limit($1)", "api_rate_limit", [current_user.id]
    )

    raise OSM::APIRateLimitExceeded if new_changes > max_changes
  end

  def scope_enabled?(scope)
    return true if basic_auth_user

    doorkeeper_token&.includes_scope?(scope)
  end

  helper_method :scope_enabled?
end
