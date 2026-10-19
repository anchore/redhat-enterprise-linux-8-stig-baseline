control 'SV-230234' do
  title 'RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user mode and maintenance.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'Note: For systems that use BIOS, this is Not Applicable.

Check the unified configuration file where the grub2 password is stored:
# grep -iw "GRUB2_PASSWORD" /boot/grub2/user.cfg
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the "GRUB2_PASSWORD" entry exists and begins with "grub.pbkdf2.sha512", this is not a finding.

Note for legacy RHEL 8 deployments: Older versions of RHEL 8 may have stored this file in the EFI partition. If the file is not found in `/boot/grub2/`, check the legacy UEFI path:
# grep -iw GRUB2_PASSWORD /boot/efi/EFI/redhat/user.cfg

If the "GRUB2_PASSWORD" entry does not exist in either location, or does not begin with "grub.pbkdf2.sha512", this is a finding.'
  desc 'fix', 'Configure the system to require a GRUB bootloader password for the grub superusers account.

Use the "grub2-setpassword" command, which automatically creates and sets the correct permissions for the unified "/boot/grub2/user.cfg" file using the required PBKDF2 SHA512 hashing algorithm.

Generate the encrypted GRUB 2 password with the following command:

# grub2-setpassword
Enter password: 
Confirm password: 

Note: Do not manually edit the GRUB configuration files to set this password; always use the provided utility to ensure the correct hashing algorithm is applied and the file is placed in the active configuration directory.'
  impact 0.7
  tag check_id: 'C-32903r1261907_chk'
  tag severity: 'high'
  tag gid: 'V-230234'
  tag rid: 'SV-230234r1262176_rule'
  tag stig_id: 'RHEL-08-010140'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-32878r1261908_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.container_system?
  end

  if file('/sys/firmware/efi').exist?
    # The unified /boot/grub2/user.cfg first, then the legacy EFI-partition path; a valid entry
    # in either location meets the requirement.
    grub_user_files = (input('grub_user_boot_files') + input('grub_uefi_user_boot_files')).uniq
    passwords = grub_user_files.select { |f| file(f).exist? }.to_h { |f| [f, parse_config_file(f).params['GRUB2_PASSWORD'].to_s] }

    describe 'The GRUB 2 superuser password' do
      it "should be set with a grub.pbkdf2.sha512 hash in one of #{grub_user_files.join(', ')}" do
        expect(passwords.values).to include(a_string_starting_with('grub.pbkdf2.sha512')),
                                    passwords.empty? ? 'No GRUB user.cfg file found' : "No GRUB2_PASSWORD beginning with grub.pbkdf2.sha512 in #{passwords.keys.join(', ')}"
      end
    end
  else
    impact 0.0
    describe 'System running BIOS' do
      skip 'The System is running BIOS, this control is Not Applicable.'
    end
  end
end
