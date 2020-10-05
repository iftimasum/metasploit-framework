module Msf::WebServices::Authentication
  module Strategies
    # autoload :ApiToken, 'msf/core/web_services/authentication/strategies/api_token'
    # autoload :AdminApiToken, 'msf/core/web_services/authentication/strategies/admin_api_token'
    # autoload :UserPassword, 'msf/core/web_services/authentication/strategies/user_password'

    Warden::Strategies.add(:api_token, Msf::WebServices::Authentication::Strategies::ApiToken)
    Warden::Strategies.add(:admin_api_token, Msf::WebServices::Authentication::Strategies::AdminApiToken)
    Warden::Strategies.add(:password, Msf::WebServices::Authentication::Strategies::UserPassword)
  end
end