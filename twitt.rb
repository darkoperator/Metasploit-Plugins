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

require 'twitter'
module Msf

	class Plugin::Twitt < Msf::Plugin
		include Msf::SessionEvent

		# Checks if the constant is already set, if not it is set
		if not defined?(Twitter_yaml)
			Twitter_yaml = "#{Msf::Config.get_config_root}/twitter.yaml"
		end

		# Initialize the Class
		def initialize(framework, opts)
			super
			add_console_dispatcher(TwittCommandDispatcher)
		end

		# Cleans up the event subscriber on unload
		def cleanup
			self.framework.events.remove_session_subscriber(self)
			remove_console_dispatcher('twitt')
		end

		# Sets the name of the Plug-In
		def name
			"twitt"
		end

		# Sets the description of the Plug-In
		def desc
			"Automatically send Twitter Direct Message when sessions are created and closed"
		end

		# Twitt Command Dispatcher Class
		class TwittCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher

			@consumer_key =  nil
			@consumer_secret =  nil
			@oauth_token =  nil
			@oauth_token_secret = nil
			@twitt_client = nil

			# Action for when a session is created
			def on_session_open(session)
				print_status("Session received Sending Message to #{@user}")
				send_direct("Source: #{@source} Session: #{session.sid} IP: #{session.session_host} Peer: #{session.tunnel_peer} Platform: #{session.platform} Type: #{session.type}")
				return
			end

			# Action for when the session is closed
			def on_session_close(session,reason = "")
				begin
					print_status("Session:#{session.sid} Type:#{session.type} is shutting down")
					send_direct("Source: #{@source} Session:#{session.sid} Type:#{session.type} is shutting down")
				rescue
					return
				end
				return
			end

			# Name of the Plug-In
			def name
				"twitt"
			end

			# Method for sending the direct message
			def send_direct(message)
				returned_message = @twitt_client.direct_message_create(@user, message)
			end

			# Reads and set the valued from a YAML File
			def read_settings
				read = nil
				if File.exist?("#{Twitter_yaml}")
					ldconfig = YAML.load_file("#{Twitter_yaml}")
					@consumer_key = ldconfig['consumer_key']
					@consumer_secret = ldconfig['consumer_secret']
					@oauth_token = ldconfig['oauth_token']
					@oauth_token_secret = ldconfig['oauth_token_secret']
					@user = ldconfig['user']
					@source = ldconfig['source']
					read = true
				else
					print_error("You must create a YAML File with the options")
					print_error("as: #{Twitter_yaml}")
					return read
				end
				return read
			end

			# Sets the commands for the Plug-In
			def commands
				{
					'twitt_help'					=> "Displays help",
					'twitt_start'					=> "Start Twitter Plugin after saving settings.",
					'twitt_stop'					=> "Stop monitoring for new sessions.",
					'twitt_test'					=> "Send test message to make sure confoguration is working.",
					'twitt_save'					=> "Save Settings to YAML File #{Twitter_yaml}.",
					'twitt_set_consumer_key'		=> "Sets Twitter Consumer Key.",
					'twitt_set_consumer_secret'	  	=> "Sets Consumer Secret.",
					'twitt_set_oauth_token'		  	=> "Sets Oauth Token.",
					'twitt_set_oauth_token_secret'  => "Sets Oauth Token Secret",
					'twitt_set_user'				=> "Sets User to whom messages will be sent.",
					'twitt_set_source'			   	=> "Sets Source Name from where the messages are sent.",
					'twitt_show_parms'			   	=> "Shows currently set parameters."

				}
			end

			# Help Command
			def cmd_twitt_help
				puts "Help"
			end

			# Re-Read YAML file and set Twitter Configuration
			def cmd_twitt_start
				print_status "Starting to monitor sessions to Twitt"
				if read_settings()
					self.framework.events.add_session_subscriber(self)
					@twitt_client = Twitter.configure do |config|
						config.consumer_key = @consumer_key
						config.consumer_secret = @consumer_secret
						config.oauth_token = @oauth_token
						config.oauth_token_secret = @oauth_token_secret
					end
					print_good("Twitter Plugin Started, Monitoring Sessions")
				else
					print_error("Could not set Twitter settings.")
				end
			end

			def cmd_twitt_stop
				print_status("Stopping the monitoring of sessions to Twitt")
				self.framework.events.remove_session_subscriber(self)
			end

			def cmd_twitt_test
				print_status("Sending tests message")
				read_settings
				@twitt_client = Twitter.configure do |config|
					config.consumer_key = @consumer_key
					config.consumer_secret = @consumer_secret
					config.oauth_token = @oauth_token
					config.oauth_token_secret = @oauth_token_secret
				end
				send_direct("This is a test Message from your Metasploit console #{::Time.now}")
				return
			end

			# Save Parameters to text file
			def cmd_twitt_save
				print_status("Saving paramters to config file")
				if @consumer_key and @consumer_secret and @oauth_token and @oauth_token_secret and @user
					config = {'consumer_key' => @consumer_key, 'consumer_secret' => @consumer_secret,
							'oauth_token' => @oauth_token, 'oauth_token_secret' => @oauth_token_secret,
							'user' => @user, 'source' => @source
					}
					File.open(Twitter_yaml, 'w') do |out|
						YAML.dump(config, out)
					end
					print_good("All parameters saved to #{Twitter_yaml}")
				else
					print_error("You have not provided all the parameters!")
				end
			end

			# Get Consumer Key
			def cmd_twitt_set_consumer_key(*args)
				if args.length > 0
					print_status("Setting the Consumer Key to #{args[0]}")
					@consumer_key = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Get Consumer Secret
			def cmd_twitt_set_consumer_secret(*args)
				if args.length > 0
					print_status("Setting the Consumer Secret to #{args[0]}")
					@consumer_secret = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Get OATH Token
			def cmd_twitt_set_oauth_token(*args)
				if args.length > 0
					print_status("Setting the OAUTH Token to #{args[0]}")
					@oauth_token = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Get Oath Token Secret
			def cmd_twitt_set_oauth_token_secret(*args)
				if args.length > 0
					print_status("Setting the OAUTH Token Secret to #{args[0]}")
					@oauth_token_secret = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Get User to whom Direct Messages Will be Sent to
			def cmd_twitt_set_user(*args)
				if args.length > 0
					print_status("Setting the DM target user to #{args[0]}")
					@user = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Set Source Name to be included in the messages
			def cmd_twitt_set_source(*args)
				if args.length > 0
					print_status("Setting the source name to #{args[0]}")
					@source = args[0]
				else
					print_error("Please provide a value")
				end
			end

			# Show the parameters set on the Plug-In
			def cmd_twitt_show_parms
				print_status("Parameters:")
				print_good("consumer_key: #{@consumer_key}")
				print_good("consumer_secret: #{@consumer_secret}")
				print_good("oauth_token: #{@oauth_token}")
				print_good("oauth_token_secret: #{@oauth_token_secret}")
				print_good("user: #{@user}")
				print_good("source: #{@source}")
			end


		end

	end
end

