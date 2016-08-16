require 'spec_helper'

describe Rails::JwtAuthentication do
  it 'has a version number' do
    expect(Rails::JwtAuthentication::VERSION).not_to be nil
  end

  it 'does something useful' do
    token = Rails::JwtAuthentication.encode({name: 'hai'})
    expect(token).to be_a(String)
  end
end
