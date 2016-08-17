require 'spec_helper'

describe Rails::JwtAuthentication do
  it 'has a version number' do
    expect(Rails::JwtAuthentication::VERSION).not_to be nil
  end

  it 'does something useful' do
    token = Rails::JwtAuthentication::Authenticate.create_jwt_token('hai', Time.now(), Time.now())
    expect(token[:auth_token]).to be_a(String)
  end
end
