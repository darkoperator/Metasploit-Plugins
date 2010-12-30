#
# $Id$
# $Revision$
#
require 'ruby-growl'
module Msf
	
	class Plugin::Growl < Msf::Plugin
		include Msf::SessionEvent
		if not defined?(Growl_yaml)
			Growl_yaml = "#{Msf::Config.get_config_root}/growl.yaml"
		end
		
		
		def initialize(framework, opts)
			super
			add_console_dispatcher(GrowlCommandDispatcher)
		end
		
		
		def cleanup
			self.framework.events.remove_session_subscriber(self)
			remove_console_dispatcher('growl')
		end
		def name
			"growl"
		end
		
		def desc
			"Automatically send Twitter Direct Message when sessions are created and closed"
		end
		
		class GrowlCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher
			
			@host =  nil
			@password =  nil
			@sticky =  true
			
			def on_session_open(session)
				print_status("Session received Sending Message to #{@host}")
				send_message("Session: #{session.sid} IP: #{session.tunnel_peer} Platform:#{session.platform} Type: #{session.type}")
				return
			end
			
			def on_session_close(session,reason = "")
			
					print_status("Session: #{session.sid} Type: #{session.type} is shutting down")
					send_message("Session: #{session.sid} Type: #{session.type} is shutting down")
				
				return
			end
			
			
			def name
				"growl"
			end
			
			def send_message(message)
				@g.notify("Session Notification","Metasploit", message,0,@sticky)
				return
			end
			
			def read_settings
				read = nil
				if File.exist?(Growl_yaml)
					ldconfig = YAML.load_file("#{Growl_yaml}")
					@host = ldconfig['host']
					@password = ldconfig['password']
					@sticky = ldconfig['sticky']
					read = true
				else
					print_error("You must create a YAML File with the options")
					print_error("as: #{Growl_yaml}")
					return read
				end
				return read
			end
			
			def commands
				{
					'growl_help'                     => "Displays help",
					'growl_start'                    => "Start Growl Plugin after saving settings.",
					'growl_save'                     => "Save Settings to YAML File #{Growl_yaml}.",
					'growl_set_host'                 => "Sets host to send message to.",
					'growl_set_password'             => "Sets password to use.",
					'growl_set_sticky'               => "Sets true or false if the message will be sticky.",
					'growl_show_parms'               => "Shows currently set parameters."
					
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
					@g  = Growl.new("localhost","Metasploit",["Session Notification"],nil,"Newsystem01")
					print_good("Growl Plugin Started, Monitoring Sessions")
				else 
					print_error("Could not set Growl settings.")
				end
			end
			
			# Save Parameters to text file
			def cmd_growl_save
				print_status("Saving paramters to config file")
				if @host and @password and @sticky
					config = {'host' => @host, 'password' => @password,
							'sticky' => @sticky
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
			
			# Get Consumer Secret
			def cmd_growl_set_password(*args)
				if args.length > 0
					print_status("Setting the password to #{args[0]}")
					@password = args[0]
				else
					print_error("Please provide a value")
				end
			end
			
			# Get OATH Token
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
			

			
			def cmd_growl_show_parms
				print_status("Parameters:")
				print_good("host #{@host}")
				print_good("password #{@password}")
				print_good("sticky #{@sticky}")
			end
			
			
		end
		
	end
end

