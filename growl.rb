# Copyright (c) 2011, Carlos Perez <carlos_perez[at]darkoperator.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and
# the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions
# and the following disclaimer in the documentation and/or other materials provided with the
# distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'ruby-growl'
module Msf

	class Plugin::Growl < Msf::Plugin
		include Msf::SessionEvent
		if not defined?(Growl_yaml)
			Growl_yaml = "#{Msf::Config.get_config_root}/growl.yaml"
		end

		# Initialize the Plug-In
		def initialize(framework, opts)
			super
			add_console_dispatcher(GrowlCommandDispatcher)
		end

		# Cleanup when the Plug-In unloads
		def cleanup
			self.framework.events.remove_session_subscriber(self)
			remove_console_dispatcher('growl')
		end
		def name
			"growl"
		end

		# Sets the description of the Plug-In
		def desc
			"Automatically send Twitter Direct Message when sessions are created and closed"
		end

		# CommandDispacher Class for the Plug-In
		class GrowlCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher

			@host	 =  nil
			@password =  nil
			@source   =  nil
			@sticky   =  true

			# Sets what is done when a session is opened
			def on_session_open(session)
				print_status("Session received Sending Message to #{@host}")
				send_message("Source: #{@source} Session: #{session.sid} IP: #{session.tunnel_peer} Platform:#{session.platform} Type: #{session.type}")
				return
			end

			# Sets what is done when a session is closed
			def on_session_close(session,reason = "")

					print_status("Session: #{session.sid} Type: #{session.type} is shutting down")
					send_message("Source: #{@source} Session: #{session.sid} Type: #{session.type} is shutting down")

				return
			end

			# Sets the name of the Plug-In
			def name
				"growl"
			end

			# Method for sending a message
			def send_message(message)
				@g.notify("Session Notification","Metasploit", message,0,@sticky)
				return
			end

			# Method for reading the YAML File
			def read_settings
				read = nil
				if File.exist?(Growl_yaml)
					ldconfig  = YAML.load_file("#{Growl_yaml}")
					@host	 = ldconfig['host']
					@password = ldconfig['password']
					@source   = ldconfig['source']
					@sticky   = ldconfig['sticky']

					read = true
				else
					print_error("You must create a YAML File with the options")
					print_error("as: #{Growl_yaml}")
					return read
				end
				return read
			end

			# Method that defines the commands of the plugin
			def commands
				{
					'growl_help'					 => "Displays help",
					'growl_start'					=> "Start Growl Plugin after saving settings.",
					'growl_save'					 => "Save Settings to YAML File #{Growl_yaml}.",
					'growl_set_host'				 => "Sets host to send message to.",
					'growl_set_password'			 => "Sets password to use.",
					'growl_set_source'			   => "Sets the source name shown in the messages.",
					'growl_set_sticky'			   => "Sets true or false if the message will be sticky.",
					'growl_show_parms'			   => "Shows currently set parameters."

				}
			end

			# Help Command
			def cmd_growl_help
				puts "Help"
			end

			# Re-Read YAML file and set Growl Configuration
			def cmd_growl_start
				print_status "Starting to monitor sessions to Growl on"
				if read_settings()
					self.framework.events.add_session_subscriber(self)
					@g  = Growl.new(@host,@source,["Session Notification"],nil,@password)
					print_good("Growl Plugin Started, Monitoring Sessions")
				else
					print_error("Could not set Growl settings.")
				end
			end

			# Save Parameters to text file
			def cmd_growl_save
				print_status("Saving paramters to config file")
				if @host and @password and @sticky and @source
					config = {'host' => @host, 'password' => @password,
							'sticky' => @sticky, 'source' => @source
					}
					File.open(Growl_yaml, 'w') do |out|
						YAML.dump(config, out)
					end
					print_good("All parameters saved to #{Growl_yaml}")
				else
					print_error("You have not provided all the parameters!")
				end
			end

			# Set Host to send message to
			def cmd_growl_set_host(*args)
				if args.length > 0
					print_status("Setting the host to #{args[0]}")
					@host = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Set Growl Password
			def cmd_growl_set_password(*args)
				if args.length > 0
					print_status("Setting the password to #{args[0]}")
					@password = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Set if message will be sticky or not
			def cmd_growl_set_sticky(*args)
				if args.length > 0
					print_status("Setting sticky to #{args[0]}")
					case args[0].downcase
					when "true"
						@sticky = true
					when "false"
						@sticky = false
					else
						print_error("Please Specify true or false")
					end
				else
					print_error("Please provide a value")
				end
			end


			# Show parameters that will be used
			def cmd_growl_show_parms
				print_status("Parameters:")
				print_good("host #{@host}")
				print_good("password #{@password}")
				print_good("sticky #{@sticky}")
				print_good("source #{@source}")
			end

			# Set the source name that will be shown in the messages
			def cmd_growl_set_source(*args)
				if args.length > 0
					print_status("Setting the source to #{args[0]}")
					@source = args[0]
				else
					print_error("Please provide a value")
				end
			end

		end

	end
end

