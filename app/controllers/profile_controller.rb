class ProfileController < ApplicationController

  require "rails/jwt_authentication"

  prepend_before_action :authenticate_user!
  respond_to :json

  def show
    render json: {
        data: {
            user: current_user.as_json
        }
    }
  end

  def update_profile
      @user = current_user
      if @user.update_attributes(update_user_params)
        render_update_success
      else
        render_update_error
      end
  end

  def change_password
    ActiveRecord::Base.transaction do
      @user = current_user

      if @user.update_with_password(update_password_params)
        time = Time.now
        jwt_token = create_jwt_token(@user, (time + 15.minutes), time)

        @user.update(token_issued_at: time)
        response.headers['Token'] = jwt_token[:auth_token]
        response.headers['Token-Expiry'] = (time + 15.minutes).to_i.to_s

        render json: {
            status: "Success",
            data: {message: "Password Successfully Updated"}
        }
      else
        render json: {
            status: "Error",
            errors: {message: @user.errors.full_messages}
        }, status: 422
      end
    end
  end


  private

  def update_user_params

    params.require(:user).permit(:first_name, :last_name, :avatar, :picture_data, :date_of_birth, :gender)

  end

  def render_update_error

    render json: {
        status: "Error",
        errors: {message: @user.errors.full_messages}
    }, status: 422

  end

  def render_update_success

    render json: {
        status: "Success",
        data: {user: @user.as_json, message: " Profile successfully updated"}
    }

  end

  def update_password_params
    params.permit(:password, :password_confirmation, :current_password)
  end
end
