# frozen_string_literal: true

require 'office365'
require 'omniauth_options'

include OmniauthOptions

# List of supported Omniauth providers.
Rails.application.config.providers = []

# Set which providers are configured.
Rails.application.config.omniauth_bn_launcher = Rails.configuration.loadbalanced_configuration
Rails.application.config.omniauth_ldap = ENV['LDAP_SERVER'].present? && ENV['LDAP_UID'].present? &&
                                         ENV['LDAP_BASE'].present?
Rails.application.config.omniauth_twitter = ENV['TWITTER_ID'].present? && ENV['TWITTER_SECRET'].present?
Rails.application.config.omniauth_google = ENV['GOOGLE_OAUTH2_ID'].present? && ENV['GOOGLE_OAUTH2_SECRET'].present?
Rails.application.config.omniauth_office365 = ENV['OFFICE365_KEY'].present? &&
                                              ENV['OFFICE365_SECRET'].present?
Rails.application.config.omniauth_openid_connect = ENV['OPENID_CONNECT_CLIENT_ID'].present? &&
                                                   ENV['OPENID_CONNECT_CLIENT_SECRET'].present? &&
                                                   ENV['OPENID_CONNECT_ISSUER'].present?
Rails.application.config.omniauth_cas = ENV['CAS_URL'].present?

SETUP_PROC = lambda do |env|
  OmniauthOptions.omniauth_options env
end

OmniAuth.config.logger = Rails.logger

# Setup the Omniauth middleware.
Rails.application.config.middleware.use OmniAuth::Builder do
  if Rails.configuration.omniauth_bn_launcher
    provider :bn_launcher, client_id: ENV['CLIENT_ID'],
      client_secret: ENV['CLIENT_SECRET'],
      client_options: { site: ENV['BN_LAUNCHER_URI'] || ENV['BN_LAUNCHER_REDIRECT_URI'] },
      setup: SETUP_PROC
  else
    Rails.application.config.providers << :ldap if Rails.configuration.omniauth_ldap

    if Rails.configuration.omniauth_twitter
      Rails.application.config.providers << :twitter

      provider :twitter, ENV['TWITTER_ID'], ENV['TWITTER_SECRET']
    end
    if Rails.configuration.omniauth_google
      Rails.application.config.providers << :google

      redirect = ENV['OAUTH2_REDIRECT'].present? ? File.join(ENV['OAUTH2_REDIRECT'], "auth", "google", "callback") : nil

      provider :google_oauth2, ENV['GOOGLE_OAUTH2_ID'], ENV['GOOGLE_OAUTH2_SECRET'],
        scope: %w(profile email),
        access_type: 'online',
        name: 'google',
        redirect_uri: redirect,
        setup: SETUP_PROC
    end
    if Rails.configuration.omniauth_office365
      Rails.application.config.providers << :office365

      redirect = ENV['OAUTH2_REDIRECT'].present? ? File.join(ENV['OAUTH2_REDIRECT'], "auth", "office365", "callback") : nil

      provider :office365, ENV['OFFICE365_KEY'], ENV['OFFICE365_SECRET'],
      redirect_uri: redirect,
        setup: SETUP_PROC
    end
    if Rails.configuration.omniauth_openid_connect
      Rails.application.config.providers << :openid_connect

      redirect = ENV['OAUTH2_REDIRECT'].present? ? File.join(ENV['OAUTH2_REDIRECT'], "auth", "openid_connect", "callback") : nil

      provider :openid_connect,
        issuer: ENV["OPENID_CONNECT_ISSUER"],
        discovery: true,
        scope: [:email, :profile],
        response_type: :code,
        uid_field: ENV["OPENID_CONNECT_UID_FIELD"] || "preferred_username",
        client_options: {
          identifier: ENV['OPENID_CONNECT_CLIENT_ID'],
          secret: ENV['OPENID_CONNECT_CLIENT_SECRET'],
          redirect_uri: redirect
        },
        setup: SETUP_PROC
    end
    if Rails.configuration.omniauth_cas
      if ENV['CAS_ROLE_FIELDS'].present?
        # for example HTTP_AFFILIATION:HTTP_HTTP_SHIB_ORGPERSON_ORGUNITNUMBER
        role_fields = ENV['CAS_ROLE_FIELDS'].split(':')
      else
        role_fields = []
      end
      # save for later use in SessionController
      Rails.application.config.omniauth_cas_role_fields = role_fields

      Rails.application.config.omniauth_cas_role_admin_regex = ENV['CAS_USER_ROLE_ADMIN_REGEX']
      Rails.application.config.omniauth_cas_auth_filter_regex = ENV['CAS_USER_AUTH_FILTER_REGEX']
      Rails.application.config.omniauth_cas_auth_filter_attribute = ENV['CAS_USER_AUTH_FILTER_ATTRIBUTE']
      Rails.application.config.providers << :cas

      provider :cas,
        url: ENV['CAS_URL'],
        service_validate_url: '/serviceValidate',
        name_key: ENV['CAS_USER_ATTRIBUTE_NAME'],
        email_key: ENV['CAS_USER_ATTRIBUTE_MAIL'],
        nickname_key: ENV['CAS_USER_ATTRIBUTE_NICKNAME'],
        first_name_key: ENV['CAS_USER_ATTRIBUTE_FIRSTNAME'],
        last_name_key: ENV['CAS_USER_ATTRIBUTE_LASTNAME'],
        image_key: ENV['CAS_USER_ATTRIBUTE_IMAGE'],
        merge_multivalued_attributes: true,
        extra_fields: role_fields
    end
  end
end

# Redirect back to login in development mode.
OmniAuth.config.on_failure = proc { |env|
  OmniAuth::FailureEndpoint.new(env).redirect_to_failure
}
