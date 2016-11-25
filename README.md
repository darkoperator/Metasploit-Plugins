# Metasploit-Plugins
Plugins for Metasploit Framework. Currently only the Pentest plugin is being maintained do to changes in Metasploit Framework that limit what gems can be loaded when the framework starts. 

## Installation

Copy the plugin you wish to use in to your .msf4/plugin folder in your home folder for your current user. To test that the plugin was properly install you can use the **load** command to load the plugin.
<pre>

msf > load pentest

       ___         _          _     ___ _           _
      | _ \___ _ _| |_ ___ __| |_  | _ \ |_  _ __ _(_)_ _
      |  _/ -_) ' \  _/ -_|_-<  _| |  _/ | || / _` | | ' \ 
      |_| \___|_||_\__\___/__/\__| |_| |_|\_,_\__, |_|_||_|
                                              |___/
      
Version 1.4
Pentest plugin loaded.
by Carlos Perez (carlos_perez[at]darkoperator.com)
[*] Successfully loaded plugin: pentest
msf > 

</pre>

## Pentest Plugin
Once the pentest plugin is loaded we can take a look at the commands added in the Console menu using the help command. This module was written so as to aid in common taks in a pentest hence the name and to aid in the logging and collection of information so as to keep a log of actions and aid in the report writing phase of a pentest.

## Auto Exploitation 

These commands are used for aiding in auto exploitation of host based on information imported from a vulnerability scanner:

<pre>
auto_exploit Commands
=====================

    Command           Description
    -------           -----------
    show_client_side  Show matched client side exploits from data imported from vuln scanners.
    vuln_exploit      Runs exploits based on data imported from vuln scanners.

</pre>

### Discovery Commands
This commands are used for the initial enumeration and additional information gathering from detected services.

<pre>
Discovery Commands
==================

    Command                 Description
    -------                 -----------
    discover_db             Run discovery modules against current hosts in the database.
    network_discover        Performs a port-scan and enumeration of services found for non pivot networks.
    pivot_network_discover  Performs enumeration of networks available to a specified Meterpreter session.
    show_session_networks   Enumerate the networks one could pivot thru Meterpreter in the active sessions.

</pre>
## Project Command
Allows the creation of projects using workspaces and the export of all data so it can be imported in to another scanner or archived. All actions are logged and timestamps for later uses in pentest reporting. All commands have help text and parameters that can be viewed using the **-h** switch. 
<pre>
Project Commands
================

    Command       Description
    -------       -----------
    project       Command for managing projects.
</pre>

## Post Exploitation Automation Commands
These command aid in the post exploitation tasks across multiple sessions and the automation of actions. 

<pre>
Postauto Commands
=================

    Command             Description
    -------             -----------
    app_creds           Run application password collection modules against specified sessions.
    multi_cmd           Run shell command against several sessions
    multi_meter_cmd     Run a Meterpreter Console Command against specified sessions.
    multi_meter_cmd_rc  Run resource file with Meterpreter Console Commands against specified sessions.
    multi_post          Run a post module against specified sessions.
    multi_post_rc       Run resource file with post modules and options against specified sessions.
    sys_creds           Run system password collection modules against specified sessions.
<pre>

