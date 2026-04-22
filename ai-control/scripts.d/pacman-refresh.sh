#!/bin/bash
# AI-Description: Refresh pacman package database (requires internet)
# AI-Confirm: yes
# AI-Network: required
# AI-Trust-Band: 400
sudo pacman -Sy --noconfirm 2>&1 | tail -10
