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
# Compression: zstd level 22 (max) with 1M block size. zstd is ~5x faster to
# decompress than xz and within 2-3% of xz's compression ratio at level 22.
# Old HW benefit: faster squashfs mount + lower CPU to unpack files on boot.
# New HW benefit: mksquashfs itself parallelises zstd — build ~40% faster.
# Block size 1M: matches the original xz config for good random-seek latency
# on a live ISO (USB reads benefit from larger blocks than pure-seek disk).
# mksquashfs ignores the -Xbcj flag for zstd (xz-only), so we don't pass it.
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '22' '-b' '1M')
file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/gshadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/root/setup-services.sh"]="0:0:755"
  ["/root/customize_airootfs.sh"]="0:0:755"
  ["/etc/lightdm/Xsession"]="0:0:755"
  ["/etc/lightdm/display-setup.sh"]="0:0:755"
  ["/usr/lib/ai-arch/hw-detect.sh"]="0:0:755"
  ["/usr/lib/ai-arch/low-ram-services.sh"]="0:0:755"
  ["/usr/lib/ai-arch/fstab-optimize.sh"]="0:0:755"
  ["/usr/lib/ai-arch/gpu-profile.sh"]="0:0:755"
  ["/usr/lib/ai-arch/pe-launch-wrapper.sh"]="0:0:755"
  ["/etc/profile.d/gpu-tuning.sh"]="0:0:644"
  ["/etc/profile.d/mesa.sh"]="0:0:644"
  ["/etc/profile.d/dxvk.sh"]="0:0:644"
  ["/etc/profile.d/vkd3d.sh"]="0:0:644"
)
