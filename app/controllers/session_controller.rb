class SessionController < Devise::SessionsController

  require "rails/jwt_authentication"

  skip_before_action :require_no_authentication
  prepend_before_action :allow_params_authentication!, only: :create
  skip_before_action :verify_signed_out_user

  respond_to :json


  # POST /user/sign_in
  def create
    user = sign_in_params[:email] ? User.find_by_email(sign_in_params[:email]) : User.find_by_phone_number(sign_in_params[:phone_number])
    if user && user.valid_password?(sign_in_params[:password])
      time = Time.now
      jwt_token = create_jwt_token(user, (time + 15.minutes), time)

      @resource = user
      if @resource.token_issued_at == nil
        @resource.update(token_issued_at: time)
      end
      response.headers['Token'] = jwt_token[:auth_token]
      if user.refresh_token.nil?
        user.update(refresh_token: create_refresh_token)
      end

      response.headers['Refresh-Token'] = user.refresh_token
      response.headers['Token-Expiry'] = (time + 15.minutes).to_i.to_s

      render_create_success
    else
      if sign_in_params[:email].present?
        msg = 'Invalid E-Mail or Password'
      else
        msg = 'Invalid Phone number or Password'
      end

      render json: {
          status: 'Error',
          errors: {
              message: msg
          }
      }, status: 401
    end
  end

  # DELETE /resource/sign_out
  def destroy
    begin
      # JWT token from header
      token = request.headers['Authorization'].split(' ').last

      # Decode the JWT token
      auth_token = JsonWebToken.decode(token)

      if auth_token && auth_token['user_id'] && !BlacklistedJwtToken.find_by_token(token)

        # Blacklist token..
        User.find(auth_token['user_id']).blacklisted_jwt_tokens.create(token: token, expiry: DateTime.strptime("#{auth_token['exp']}", '%s'))

        render json: {
            message: "Logged out"
        }, status: 200
      else
        render json: {:status => "error", errors: "Not Authenticated"}, status: 401
      end
    rescue => e
      if e.message == 'Signature has expired'
        render json: {:status => "error", errors: 'Token Expired'}, status: 440
      else
        render json: {:status => "error", errors: 'Not Authenticated'}, status: 401
      end
    end
  end


  # Get JWT refresh token
  def refresh_token

    # Refresh token from header
    if request.headers['Refresh-Token'].present?
      user = User.find_by_refresh_token(request.headers['Refresh-Token'])
    end

    unless user.nil?
      time = Time.now
      jwt_token = create_jwt_token(user, (time + 15.minutes), time)
      response.headers['Token'] = jwt_token[:auth_token]
      response.headers['Token-Expiry'] = (time + 15.minutes).to_i.to_s
      render json: {:status => "Success"}, status: 200
      return
    end

    render json: {:status => "error", errors: "Not Authenticated"}, status: 401
  end


  # Delete expired tokens from blacklisted_jwt_tokens table
  def delete_token
    expired_tokens = BlacklistedJwtToken.expired
    if expired_tokens
      expired_tokens.delete_all
    end

    render nothing: true
  end


  protected

  def sign_in_params
    devise_parameter_sanitizer.sanitize(:sign_in)
  end

  private

  def render_create_success
    if @resource.confirmed_at.present? && @resource.phone_verified_at.present?
      status = "active"
      message = "Login success"
    else
      status = "Not confirmed"
      message = "Your account need to be verified to progress"
    end
    render json: {
        status: status,
        data: {:user_id => @resource.id, :user_token => @resource.user_token, :first_name => @resource.first_name, :last_name => @resource.last_name, :email => @resource.email, :phone_number => @resource.phone_number, "email_confirmed" => @resource.confirmed_at.present?, "phone_verified" => @resource.phone_verified_at.present?, "avatar" => @resource.avatar_url, :date_of_birth => @resource.date_of_birth, :gender => @resource.gender, :message => message}
    }
  end

end