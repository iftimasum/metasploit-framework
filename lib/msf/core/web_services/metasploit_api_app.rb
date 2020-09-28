require 'securerandom'
require 'sinatra/base'
require 'swagger/blocks'
require 'warden'
require 'msf/core/web_services/authentication'
#require 'msf/core/web_services/servlet_helper'
#require 'msf/core/web_services/servlet/api_docs_servlet'
#require 'msf/core/web_services/servlet/auth_servlet'
#require 'msf/core/web_services/servlet/host_servlet'
#require 'msf/core/web_services/servlet/note_servlet'
#require 'msf/core/web_services/servlet/vuln_servlet'
#require 'msf/core/web_services/servlet/event_servlet'
#require 'msf/core/web_services/servlet/web_servlet'
#require 'msf/core/web_services/servlet/msf_servlet'
#require 'msf/core/web_services/servlet/workspace_servlet'
#require 'msf/core/web_services/servlet/service_servlet'
#require 'msf/core/web_services/servlet/session_servlet'
#require 'msf/core/web_services/servlet/exploit_servlet'
#require 'msf/core/web_services/servlet/loot_servlet'
#require 'msf/core/web_services/servlet/session_event_servlet'
#require 'msf/core/web_services/servlet/credential_servlet'
#require 'msf/core/web_services/servlet/login_servlet'
#require 'msf/core/web_services/servlet/nmap_servlet'
#require 'msf/core/web_services/servlet/db_export_servlet'
#require 'msf/core/web_services/servlet/vuln_attempt_servlet'
#require 'msf/core/web_services/servlet/user_servlet'
#require 'msf/core/web_services/servlet/payload_servlet'
#require 'msf/core/web_services/servlet/module_search_servlet'
#require 'msf/core/web_services/servlet/db_import_servlet'

class Msf::WebServices::MetasploitApiApp < Sinatra::Base
  helpers Msf::WebServices::ServletHelper

  # Servlet registration
  register Msf::WebServices::ApiDocsServlet
  register Msf::WebServices::AuthServlet
  register Msf::WebServices::HostServlet
  register Msf::WebServices::VulnServlet
  register Msf::WebServices::EventServlet
  register Msf::WebServices::WebServlet
  register Msf::WebServices::MsfServlet
  register Msf::WebServices::NoteServlet
  register Msf::WebServices::WorkspaceServlet
  register Msf::WebServices::ServiceServlet
  register Msf::WebServices::SessionServlet
  register Msf::WebServices::ExploitServlet
  register Msf::WebServices::LootServlet
  register Msf::WebServices::SessionEventServlet
  register Msf::WebServices::CredentialServlet
  register Msf::WebServices::LoginServlet
  register Msf::WebServices::NmapServlet
  register Msf::WebServices::DbExportServlet
  register Msf::WebServices::VulnAttemptServlet
  register Msf::WebServices::UserServlet
  register Msf::WebServices::PayloadServlet
  register Msf::WebServices::ModuleSearchServlet
  register Msf::WebServices::DbImportServlet
  configure do
    set :sessions, {key: 'msf-ws.session', expire_after: 300}
    set :session_secret, ENV.fetch('MSF_WS_SESSION_SECRET') { SecureRandom.hex(16) }
  end

  before do
    # store DBManager in request environment so that it is available to Warden
    request.env['msf.db_manager'] = get_db
    # store flag indicating whether authentication is initialized in the request environment
    @@auth_initialized ||= get_db.users({}).count > 0
    request.env['msf.auth_initialized'] = @@auth_initialized
  end

  use Warden::Manager do |config|
    # failed authentication is handled by this application
    config.failure_app = self
    # don't intercept 401 responses since the app will provide custom failure messages
    config.intercept_401 = false
    config.default_scope = :api

    config.scope_defaults :user,
                          # whether to persist the result in the session or not
                          store: true,
                          # list of strategies to use
                          strategies: [:password],
                          # action (route) of the failure application
                          action: "#{Msf::WebServices::AuthServlet.api_unauthenticated_path}/user"

    config.scope_defaults :api,
                          # whether to persist the result in the session or not
                          store: false,
                          # list of strategies to use
                          strategies: [:api_token],
                          # action (route) of the failure application
                          action: Msf::WebServices::AuthServlet.api_unauthenticated_path

    config.scope_defaults :admin_api,
                          # whether to persist the result in the session or not
                          store: false,
                          # list of strategies to use
                          strategies: [:admin_api_token],
                          # action (route) of the failure application
                          action: Msf::WebServices::AuthServlet.api_unauthenticated_path
  end

end
