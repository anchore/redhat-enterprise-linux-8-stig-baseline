control 'SV-230531' do
  title 'The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify RHEL 8 is configured to not reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ sudo grep -iR CtrlAltDelBurstAction /etc/systemd/system*
/etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf:CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to disable the CtrlAltDelBurstAction by adding it to a drop file in a "/etc/systemd/system.conf.d/" configuration file:

If no drop file exists, create one with the following command:

$ sudo mkdir -p /etc/systemd/system.conf.d && sudo vi /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf

Edit the file to contain the setting by adding the following text:

[Manager]
CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.7
  tag check_id: 'C-33200r1208753_chk'
  tag severity: 'high'
  tag gid: 'V-230531'
  tag rid: 'SV-230531r1262161_rule'
  tag stig_id: 'RHEL-08-040172'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33175r1261882_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  # systemd reads system.conf, then the *.conf drop-ins in filename order (a file in /etc
  # overrides one of the same name in /run or /usr/lib), and only [Manager] settings count.
  # The last assignment wins; files without a .conf suffix are ignored.
  dropin_dirs = ['/usr/lib/systemd/system.conf.d', '/run/systemd/system.conf.d', '/etc/systemd/system.conf.d']
  dropins = dropin_dirs.each_with_object({}) { |dir, found|
    command("find #{dir} -maxdepth 1 -name '*.conf' 2>/dev/null").stdout.split("\n").each { |f| found[File.basename(f)] = f }
  }
  config_files = ['/etc/systemd/system.conf'] + dropins.sort.map(&:last)

  setting = nil
  config_files.each do |f|
    section = nil
    file(f).content.to_s.each_line do |line|
      line = line.strip
      if line =~ /^\[(.+)\]$/
        section = Regexp.last_match(1)
      elsif section == 'Manager' && line =~ /^CtrlAltDelBurstAction\s*=\s*(.*)$/
        setting = { file: f, value: Regexp.last_match(1).strip }
      end
    end
  end

  describe 'The systemd CtrlAltDelBurstAction setting' do
    it 'should be set to none' do
      expect(setting&.dig(:value)).to eq('none'),
                                      setting ? "CtrlAltDelBurstAction is set to '#{setting[:value]}' in #{setting[:file]}" : "CtrlAltDelBurstAction is not set under [Manager] in #{config_files.join(', ')}"
    end
  end
end
