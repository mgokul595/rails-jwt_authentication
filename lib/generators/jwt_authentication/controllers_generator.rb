require 'rails/generators'

module JwtAuthentication
  class ControllersGenerator < Rails::Generators::Base
    CONTROLLERS = %w(profile registration session)

    source_root File.expand_path("../../templates/controllers", __FILE__)

    class_option :controllers, aliases: "-c", type: :array,
                 desc: "Select specific controllers to generate (#{CONTROLLERS.join(', ')})"

    def create_controllers
      controllers = options[:controllers] || CONTROLLERS
      controllers.each do |name|
        template "#{name}_controller.rb",
                 "app/controllers/#{name}_controller.rb"
      end
    end

  end
end
