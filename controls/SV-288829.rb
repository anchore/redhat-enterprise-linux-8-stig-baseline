control 'SV-288829' do
  title 'RHEL 8 must implement DoW-approved encryption in the OpenSSL package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoW nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config file.'
  desc 'check', 'Verify the RHEL 8 OpenSSL library is configured to use only ciphers employing FIPS 140-3-approved algorithms with the following command:

$ grep -i opensslcnf.config /etc/pki/tls/openssl.cnf
.include = /etc/crypto-policies/back-ends/opensslcnf.config

If the "opensslcnf.config" is not defined in the "/etc/pki/tls/openssl.cnf" file, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 OpenSSL library to use the systemwide cryptographic policy.

Edit the "/etc/pki/tls/openssl.cnf" and add or modify the following line:

.include = /etc/crypto-policies/back-ends/opensslcnf.config'
  impact 0.7
  tag check_id: 'C-93518r1261886_chk'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-288829'
  tag rid: 'SV-288829r1261888_rule'
  tag stig_id: 'RHEL-08-010293'
  tag fix_id: 'F-93423r1261887_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container'

  openssl_cnf = '/etc/pki/tls/openssl.cnf'

  describe file(openssl_cnf) do
    it { should exist }
    its('content') { should match(%r{^\s*\.include\s*=?\s*/etc/crypto-policies/back-ends/opensslcnf\.config\s*$}i) }
  end
end
