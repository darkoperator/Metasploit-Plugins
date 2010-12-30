#
# $Id$
# $Revision$
#
require 'twitter'
module Msf
	
	class Plugin::Twitt < Msf::Plugin
		include Msf::SessionEvent
		if not defined?(Twitter_yaml)
			Twitter_yaml = "#{Msf::Config.get_config_root}/twitter.yaml"
		end
		
		
		def initialize(framework, opts)
			super
			add_console_dispatcher(TwittCommandDispatcher)
		end
		
		
		def cleanup
			self.framework.events.remove_session_subscriber(self)
			remove_console_dispatcher('twitt')
		end
		def name
			"twitt"
		end
		
		def desc
			"Automatically send Twitter Direct Message when sessions are created and closed"
		end
		
		class TwittCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher
			
			@consumer_key =  nil
			@consumer_secret =  nil
			@oauth_token =  nil
			@oauth_token_secret = nil
			
			def on_session_open(session)
				print_status("Session received Sending Message to #{@user}")
				send_direct("MSFTwitter Session:#{session.sid} IP:#{session.tunnel_peer} Platform:#{session.platform} Type:#{session.type}")
				return
			end
			
			def on_session_close(session,reason = "")
				begin
					print_status("Session:#{session.sid} Type:#{session.type}is shutting down")
					send_direct("Session:#{session.sid} Type:#{session.type}is shutting down")
				rescue
					return
				end
				return
			end
			
			
			def name
				"twitt"
			end
			
			def send_direct(message)
				Twitter.direct_message_create(@user, message)
				return
			end
			
			def read_settings
				read = nil
				if File.exist?("#{Twitter_yaml}")
					ldconfig = YAML.load_file("#{Twitter_yaml}")
					@consumer_key = ldconfig['consumer_key']
					@consumer_secret = ldconfig['consumer_secret']
					@oauth_token = ldconfig['oauth_token']
					@oauth_token_secret = ldconfig['oauth_token_secret']
					@user = ldconfig['user']
					read = true
				else
					print_error("You must create a YAML File with the options")
					print_error("as: #{Twitter_yaml}")
					return read
				end
				return read
			end
			
			def commands
				{
					'twitt_help'                     => "Displays help",
					'twitt_start'                    => "Start Twitter Plugin after saving settings.",
					'twitt_save'                     => "Save Settings to YAML File #{Twitter_yaml}.",
					'twitt_set_consumer_key'         => "Sets Twitter Consumer Key.",
					'twitt_set_consumer_secret'      => "Sets Consumer Secret.",
					'twitt_set_oauth_token'          => "Sets Oauth Token.",
					'twitt_set_oauth_token_secret'   => "Sets Oauth Token Secret",
					'twitt_set_user'                 => "Sets User to whom messages will be sent.",
					'twitt_show_parms'               => "Shows currently set parameters."
					
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
					Twitter.configure do |config|
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
			
			# Save Parameters to text file
			def cmd_twitt_save
				print_status("Saving paramters to config file")
				if @consumer_key and @consumer_secret and @oauth_token and @oauth_token_secret and @user
					config = {'consumer_key' => @consumer_key, 'consumer_secret' => @consumer_secret,
							'oauth_token' => @oauth_token, 'oauth_token_secret' => @oauth_token_secret,
							'user' => @user
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
			
			def cmd_twitt_show_parms
				print_status("Parameters:")
				print_good("consumer_key: #{@consumer_key}")
				print_good("consumer_secret: #{@consumer_secret}")
				print_good("oauth_token: #{@oauth_token}")
				print_good("oauth_token_secret: #{@oauth_token_secret}")
				print_good("user: #{@user}")
			end
			
			
		end
		
	end
end

