control 'SV-230280' do
  title 'RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 implements ASLR with the following command:

$ sudo sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -rs kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf
/etc/sysctl.d/99-kernel_randomize_va_space.conf:kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", or is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure RHEL 8 to implement virtual address space randomization.

$ echo 'kernel.randomize_va_space = 2' | sudo tee /etc/sysctl.d/99-kernel_randomize_va_space.conf

Remove any configurations that conflict with the above from the following locations: 

/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Issue the following command to make the changes take effect:

$ sudo sysctl --system)
  impact 0.5
  tag check_id: 'C-32949r1208743_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-230280'
  tag rid: 'SV-230280r1208745_rule'
  tag stig_id: 'RHEL-08-010430'
  tag fix_id: 'F-32924r1208744_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.container_system?
  }

  parameter = 'kernel.randomize_va_space'
  value = 2
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  describe kernel_parameter(parameter) do
    its('value') { should eq value }
  end

  search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

  correct_result = search_results.any? { |line| line.match(regexp) }
  incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

  describe 'Kernel config files' do
    it "should configure '#{parameter}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
