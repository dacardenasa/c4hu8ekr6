class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :null_session

  def basic_auth
   authenticate_or_request_with_http_basic do |username, token|
     user = User.find_by_email(username)
     if user.api_token == token
       sign_in user
     else
       head 401
     end
   end
  end

end
