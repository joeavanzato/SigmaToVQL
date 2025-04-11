

This is a list of the categories, products and services we should attempt to map to when considering Sigma with respect to Velociraptor.

If there is a specific log source to map - check out https://sigmahq.io/docs/basics/log-sources.html to see if anything aligns well from an artifact perspective.

### Default Categories
* antivirus
* accounting
* application
* create_remote_thread
* dns
* dns_query
* driver_load
* firewall
* file_event
* file_access
* file_block
* file_change
* file_delete
* file_rename
* image_load
* network_connection
* pipe_created
* process_access
* process_creation
* process_tampering
* proxy
* ps_classic_provider_start
* ps_classic_start
* ps_module
* ps_script
* raw_access_thread
* registry_add
* registry_delete
* registry_event
* registry_set
* security
* sysmon_error
* sysmon_status
* system
* wmi_event
* webserver

### Default Products
This is a list of the products we should care about when considering Sigma with respect to Velociraptor use-cases.
* windows
* linux
* macos

### Default Services
* apache
* auditd
* auth
* cron
* guacamole
* modsecurity
* sshd
* syslog
* vsftpd
* application
* applocker
* bits-client
* codeintegrity-operational
* dns-server
* diagnosis-scripted
* driver-framework
* firewall-as
* ldap_debug
* microsoft-servicebus-client
* msexchange-management
* ntlm
* openssh
* powershell
* powershell-classic
* printservice-admin
* printservice-operational
* security
* security-mitigations
* shell-core
* smbclient-security
* sysmon
* system
* terminalservices-localsessionmanager
* wmi



### New Services
* taskscheduler
* dnscache
* dlls
* servicces
* rootcastore
* hostsfile
* amcache
* pslist
* psreadline
* moduleanalysiscache
* timeline
* certutil
* recentapps
* lnk
* prefetch
* bam
* usn
* installedsoftware
* startupitems