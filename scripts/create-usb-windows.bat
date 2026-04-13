@echo off
REM create-usb-windows.bat — Instructions for creating AI Arch Linux USB on Windows
REM
REM This script helps you create a bootable USB drive with persistence.

echo =========================================
echo   AI Arch Linux - USB Drive Creator
echo =========================================
echo.
echo STEP 1: Download Rufus (if you don't have it)
echo   https://rufus.ie/
echo.
echo STEP 2: Write the ISO to USB
echo   - Open Rufus
echo   - Select your USB drive
echo   - Click SELECT and choose the ISO file:
echo     %~dp0..\output\ai-arch-linux-*.iso
echo   - Set "Partition scheme" to "GPT" (for UEFI)
echo     or "MBR" (for legacy BIOS)
echo   - Click START
echo   - Choose "Write in DD Image mode" when prompted
echo.
echo STEP 3: Add persistence partition (optional)
echo   After Rufus finishes:
echo   - Open Disk Management (Win+X, Disk Management)
echo   - Find your USB drive
echo   - Right-click the unallocated space after the ISO
echo   - Create New Simple Volume
echo   - Format as ext4 (or leave unformatted — Linux will format it)
echo   - NOTE: Windows can't create ext4, so use WSL instead:
echo.
echo     wsl -d Arch -- bash -c "
echo       # Find your USB partition (check with lsblk first!)
echo       sudo mkfs.ext4 -L AI_PERSIST /dev/sdX3
echo     "
echo.
echo STEP 4: Boot from USB
echo   - Plug USB into target computer
echo   - Enter BIOS boot menu (F12, F2, or Del)
echo   - Select USB drive
echo   - Choose "Persistent USB" from boot menu
echo.
echo =========================================
echo.
pause
