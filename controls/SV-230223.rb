control 'SV-230223' do
  title 'RHEL 8 must implement a FIPS 140-3-compliant systemwide cryptographic policy.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', %q(Verify RHEL 8 is set to use a FIPS 140-3-compliant systemwide cryptographic policy.

Verify the current systemwide crypto-policy with the following command:

$ update-crypto-policies --show
FIPS

If the systemwide crypto-policy is not set to "FIPS", this is a finding.

Verify the current minimum crypto-policy configuration with the following commands:

$ sudo grep -E 'rsa_size|hash' /etc/crypto-policies/state/CURRENT.pol
hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512
min_rsa_size = 2048

If the "hash" values do not include at least the following FIPS 140-3-compliant algorithms, this is a finding:

"SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512"

If any algorithms include "SHA1" or a hash value less than "224", this is a finding.

If the "min_rsa_size" is not set to a value of at least "2048", this is a finding.

If these commands do not return any output, this is a finding.)
  desc 'fix', 'Configure RHEL 8 to use a FIPS 140-3-compliant systemwide cryptographic policy.

Set the systemwide crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS
Setting system policy to FIPS

Note: Systemwide crypto-policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-32892r1261898_chk'
  tag severity: 'high'
  tag gid: 'V-230223'
  tag rid: 'SV-230223r1262171_rule'
  tag stig_id: 'RHEL-08-010020'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-32867r1261899_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.container_system?
  }

  describe command('update-crypto-policies --show') do
    its('stdout.strip') { should eq 'FIPS' }
  end

  describe parse_config_file('/etc/crypto-policies/state/CURRENT.pol') do
    its(['min_rsa_size']) { should cmp >= 2048 }
    its(['hash']) {
      should include 'SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA2-224',
                     'SHA3-256', 'SHA3-384', 'SHA3-512'
    }
    its(['hash']) { should_not match(/SHA-?1\b/i) }
    its(['hash']) {
      is_expected.to satisfy('no hash size < 256 (except 224)') { |s|
                       sizes = s.scan(/-(\d+)/).flatten.map(&:to_i)
                       (sizes - [224]).all? { |n| n >= 256 }
                     }
    }
  end
end
