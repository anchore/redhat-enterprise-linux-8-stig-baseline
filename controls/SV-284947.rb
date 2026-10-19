control 'SV-284947' do
  title 'RHEL 8 must use a reverse-path filter for IPv4 network traffic, when possible, by default.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface on which they were received. It must not be used on systems that are routers for complicated networks but is helpful for end hosts and routers serving small networks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 uses reverse path filtering on IPv4 interfaces.

Check the value of the "net.ipv4.conf.default.rp_filter" with the following command:

$ sudo sysctl net.ipv4.conf.default.rp_filter
net.ipv4.conf.default.rp_filter = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to use reverse path filtering on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_rp_filter.conf

Add the following line to the file:

net.ipv4.conf.default.rp_filter = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-89516r1208424_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-284947'
  tag rid: 'SV-284947r1210519_rule'
  tag stig_id: 'RHEL-08-040287'
  tag fix_id: 'F-89421r1210518_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
  tag 'host'

  describe 'TODO' do
    skip 'Automated test for SV-284947 not yet implemented'
  end
end
