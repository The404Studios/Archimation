#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="archwindows"
iso_label="ARCHWIN_$(date +%Y%m)"
iso_publisher="ArchWindows - modified by fourzerofour"
iso_application="ArchWindows Live/Install"
iso_version="$(date +%Y.%m.%d)"
install_dir="arch"
buildmodes=('iso')
bootmodes=('bios.syslinux'
            'uefi-x64.grub.esp'
            'uefi-x64.grub.eltorito')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/gshadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/root/setup-services.sh"]="0:0:755"
  ["/root/customize_airootfs.sh"]="0:0:755"
  ["/etc/lightdm/Xsession"]="0:0:755"
  ["/etc/lightdm/display-setup.sh"]="0:0:755"
)
