require 'jwt'

module Rails
  module JwtAuthentication
    class JsonWebToken
      def self.encode(payload)
        JWT.encode(payload, 'Rails.application.secrets.secret_key_base')
      end

      def self.decode(token, leeway = 0)
        HashWithIndifferentAccess.new(
            JWT.decode(token,
                       Rails.application.secrets.secret_key_base,
                       true,
                       {
                           verify_iat: true,
                           leeway: leeway
                       }
            )[0]
        )
      end
    end

  end
end