# ~/.bashrc - default user shell init (ARCHWINDOWS)
#
# Session 69 (Agent R).  customize_airootfs.sh may overlay a richer bashrc
# from /usr/share/ai-desktop-config/skel/bashrc; this file is the minimal
# fallback when that package's skel hasn't been shipped yet.  Appending
# here is safe because customize_airootfs runs AFTER useradd's copy of
# /etc/skel, so a later overlay wins.

# If not running interactively, don't do anything
[[ $- != *i* ]] && return

# History
HISTSIZE=5000
HISTFILESIZE=10000
HISTCONTROL=ignoreboth:erasedups
shopt -s histappend

# Prompt
PS1='\[\e[1;34m\]\u@\h\[\e[0m\] \[\e[1;32m\]\w\[\e[0m\]\$ '

# Aliases
alias ls='ls --color=auto'
alias ll='ls -lah'
alias grep='grep --color=auto'

# --- ARCHWINDOWS onboarding --------------------------------------------
# The AI daemon runs on localhost:8420 and needs the "trust" + "pe-compat"
# groups for full access.  setup-users.sh puts the default user in those
# on first boot; if you're reading this from a fresh-install shell and
# `id` doesn't show them, run:  sudo /root/setup-users.sh
#
# Useful entry points:
#   ai-health          -- system diagnostics (see Agent Q's work)
#   ai                 -- CLI client for the daemon
#   pe-status          -- PE loader / runtime diagnostics
#   contusion          -- natural-language system control
#
# Documentation:
#   /usr/share/doc/ARCHWINDOWS/USER-MANUAL.md     -- operator manual
#   /usr/share/doc/ARCHWINDOWS/permissions.md     -- group/permission model
#
# The first time you log in, `ai-health` is a good smoke test.
