control 'SV-288830' do
  title 'The RHEL 8 SSH daemon must be configured to use systemwide crypto policies.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoW nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.'
  desc 'check', 'Verify that systemwide crypto policies are in effect:

$ sudo grep CRYPTO_POLICY /etc/sysconfig/sshd
# CRYPTO_POLICY=

If the "CRYPTO_POLICY " is uncommented, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 SSH daemon to use systemwide crypto policies by adding the following line to /etc/sysconfig/sshd:

# CRYPTO_POLICY=

Restart the sshd service:
$ sudo systemctl restart sshd'
  impact 0.7
  tag check_id: 'C-93519r1261889_chk'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-288830'
  tag rid: 'SV-288830r1261891_rule'
  tag stig_id: 'RHEL-08-010287'
  tag fix_id: 'F-93424r1261890_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'

  describe 'TODO' do
    skip 'Automated test for SV-288830 not yet implemented'
  end
end
