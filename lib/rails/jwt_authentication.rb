require "rails/jwt_authentication/version"
require 'jwt'

module Rails
  module JwtAuthentication

    class Authenticate

      # To authenticate user with JWT Token
      def authenticate_user!(leeway = 0)
        begin
          unless user_id_in_token?(leeway) && logged_in? && valid_token_issued_time?
            render json: {error: 'Not Authenticated'}, status: 401
            return
          end

          @current_user = User.find(auth_token['user_id'])

        rescue => e
          if e.message == 'Signature has expired'
            render json: {:status => "error", errors: 'Token Expired'}, status: 440
          else
            render json: {:status => "error", errors: 'Not Authenticated'}, status: 401
          end
        end
      end

      # To create a new JWT Token after validating user
      def create_jwt_token(user, exp_time, iat_time)
        return nil unless user and user.id
        {
            auth_token: JsonWebToken.encode(
                {
                    user_id: user.id,
                    exp: exp_time.to_i,
                    iat: iat_time.to_i
                }
            ),
        }
      end

      def create_refresh_token
        loop do
          random_token = SecureRandom.urlsafe_base64
          return random_token unless User.exists?(refresh_token: random_token)
        end
      end


      private

      def http_token
        @http_token ||= if request.headers['Authorization'].present?
                          request.headers['Authorization'].split(' ').last
                        end
      end

      def auth_token(leeway = 0)
        @auth_token ||= JsonWebToken.decode(http_token, leeway)
      end

      def user_id_in_token?(leeway)
        http_token && auth_token(leeway) && auth_token(leeway)['user_id'].to_i
      end

      def logged_in?
        !BlacklistedJwtToken.find_by_token(request.headers['Authorization'].split(' ').last)
      end

      def valid_token_issued_time?
        user = User.find(auth_token['user_id'])
        !user.token_issued_at.nil? && (Time.at(auth_token['iat']).to_i >= user.token_issued_at.to_i)
      end
    end


  end
end
