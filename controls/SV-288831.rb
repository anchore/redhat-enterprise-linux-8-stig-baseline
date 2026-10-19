control 'SV-288831' do
  title 'OS must generate an audit record for all successful and unsuccessful uses of the useradd command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The useradd command modifies the system account files to reflect the changes that are specified on the command line.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.'
  desc 'check', 'Verify OS generates an audit record for any successful and unsuccessful use of the "useradd" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":
  
$ grep -w useradd /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OS to generate an audit event for any successful and unsuccessful uses of the "useradd" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd

The audit daemon must be restarted for the changes to take effect.

$ service auditd restart'
  impact 0.5
  tag check_id: 'C-93520r1261901_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000466-GPOS-00210"']
  tag gid: 'V-288831'
  tag rid: 'SV-288831r1261903_rule'
  tag stig_id: 'RHEL-08-030565'
  tag fix_id: 'F-93425r1261902_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  describe 'TODO' do
    skip 'Automated test for SV-288831 not yet implemented'
  end
end
