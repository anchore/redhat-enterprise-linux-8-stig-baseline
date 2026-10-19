control 'SV-284949' do
  title 'RHEL 8 must log IPv4 packets with impossible addresses by default.'
  desc 'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.

Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoW or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional system information as a nonprivileged user.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 logs IPv4 martian packets by default.

Check the value of the "default.log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.log_martians
net.ipv4.conf.default.log_martians = 1

If "net.ipv4.conf.default.log_martians" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to log martian packets on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.default.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-89518r1208430_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-284949'
  tag rid: 'SV-284949r1262226_rule'
  tag stig_id: 'RHEL-08-040222'
  tag fix_id: 'F-89423r1208758_fix'
  tag cci: ['CCI-002386']
  tag nist: ['SC-5']
  tag 'host'

  describe 'TODO' do
    skip 'Automated test for SV-284949 not yet implemented'
  end
end
