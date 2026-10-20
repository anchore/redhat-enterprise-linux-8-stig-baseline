control 'SV-244521' do
  title 'RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require a unique superusers name upon booting into single-user mode and maintenance.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

The GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of nonunique superusers names are root, superuser, unlock, etc.'
  desc 'check', 'Note: For systems that use BIOS, this is Not Applicable.

Verify that a unique name is set as the "superusers" account.

Search the unified GRUB 2 configuration file for the superusers definition:
# grep -iw "superusers" /boot/grub2/grub.cfg
set superusers="[someuniquestringhere]"
export superusers

If "superusers" is not defined, or if the defined superuser name is identical to a standard OS administrative account name (such as "root", "admin", "administrator", "superuser", or "unlock"), this is a finding.

Note for legacy RHEL 8 deployments: If the system is running an older minor release where GRUB paths are not unified, check the legacy UEFI path:
# grep -iw "superusers" /boot/boot/efi/EFI/redhat/grub.cfg'
  desc 'fix', 'Configure the system to have a unique name for the GRUB 2 superusers account.

1. Edit the "/etc/grub.[...](asc_slot://start-slot-10)d/01_users" file to declare the custom superuser name:

# pfedit /etc/grub.d/01_users

Ensure the following lines exist or are modified:
set superusers="[someuniquestringhere]"
export superusers
password_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}
(Replace "[someuniquestringhere]" with a unique string that does not match any existing OS user account name.)

2. Regenerate the GRUB 2 configuration using the unified configuration utility:

# grub2-mkconfig -o /boot/grub2/grub.cfg

Note for legacy RHEL 8 deployments: If using an older minor release requiring the legacy partition file path, output the config to:
# grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg'
  impact 0.5
  tag check_id: 'C-47796r1261910_chk'
  tag severity: 'medium'
  tag gid: 'V-244521'
  tag rid: 'SV-244521r1262177_rule'
  tag stig_id: 'RHEL-08-010141'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-47753r1261911_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.container_system?
  }

  if file('/sys/firmware/efi').exist?
    # The unified /boot/grub2/grub.cfg first, then the legacy EFI-partition path.
    grubfile_paths = [input('grub_main_cfg'), input('grub_uefi_main_cfg')].uniq
    superusers_account = grubfile_paths.lazy.map { |path|
      superusers_match = file(path).content.to_s.match(/^\s*set\s+superusers=(?:"([^"]+)"|(\S+))/)
      superusers_match && (superusers_match[1] || superusers_match[2])
    }.find(&:itself)
    disallowed_superusers = (input('disallowed_grub_superusers') + passwd.users).uniq

    describe 'The GRUB superuser' do
      it "should be set in a GRUB config file (#{grubfile_paths.join(', ')})" do
        expect(superusers_account).not_to be_nil, "No superuser account set in #{grubfile_paths.join(' or ')}"
      end

      unless superusers_account.nil?
        it 'should not match an OS account name or default GRUB superuser name' do
          expect(disallowed_superusers).not_to include(superusers_account), "Superuser account is set to non-unique or easily guessed username '#{superusers_account}'"
        end
      end
    end
  else
    impact 0.0
    describe 'System running BIOS' do
      skip 'The System is running BIOS, this control is Not Applicable.'
    end
  end
end
