class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :null_session

  def basic_auth
    email = request.headers["X-User-Email"]
    token = request.headers["X-Api-Token"]
    user = User.find_by_email(email)

    if user.api_token == token
      sign_in user
    else
      head 401
    end
    # Authenticate with http_request_basic
    # authenticate_or_request_with_http_basic do |username, token|
    #   user = User.find_by_email(username)
    #   if user.api_token == token
    #     sign_in user
    #   end
    # end
  end

end
