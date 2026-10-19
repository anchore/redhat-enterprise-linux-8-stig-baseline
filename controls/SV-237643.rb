control 'SV-237643' do
  title 'RHEL 8 must require re-authentication when using the "sudo" command.'
  desc %q(Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.

If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

$ sudo grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
/etc/sudoers:Defaults timestamp_timeout=0

If results are returned from more than one file location, this is a finding.

If "timestamp_timeout" is set to a value other than "0" (including negative numbers), is commented out, or is missing entirely, this is a finding.)
  desc 'fix', 'Configure the OS to reauthenticate every invocation of the "sudo" command.

Add the following line to "/etc/sudoers" or a file in "/etc/sudoers.d":

Defaults timestamp_timeout=0

Remove any duplicate definitions.'
  impact 0.5
  tag check_id: 'C-40862r1262532_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag gid: 'V-237643'
  tag rid: 'SV-237643r1262533_rule'
  tag stig_id: 'RHEL-08-010384'
  tag fix_id: 'F-40825r1261914_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable in a container with no sudo installed', impact: 0.0) {
    !virtualization.container_system? || command('sudo').exist?
  }

  setting = 'timestamp_timeout'
  setting_value = sudoers(input('sudoers_config_files')).settings.Defaults[setting]

  describe 'Sudoers configuration' do
    it "should should set #{setting} to a non-negative number, exactly once" do
      expect(setting_value).to_not be_nil, "#{setting} not found inside sudoers config file(s)"
      expect(setting_value.count).to eq(1), "#{setting} set #{setting_value.count} times inside sudoers config file(s)"
      expect(setting_value.first.to_i).to be >= 0
    end
  end
end
