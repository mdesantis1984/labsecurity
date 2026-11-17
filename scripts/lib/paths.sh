# shellcheck shell=bash
# Where LabSecurity keeps its files. Source this file; it defines labsec_resolve_paths.
# The same rules are implemented in labsec/config.py (default_dirs); tests/unit/test_layout.py keeps both in step.
# Compatible with bash 3.2 (macOS): no associative arrays, no ${var,,}, no mapfile.
#
#   LABSEC_HOME set     everything under it: config/ cache/ state/ and the data itself
#   macOS               the same layout under ~/Library/Application Support/LabSecurity
#   Linux and WSL2      XDG: $XDG_DATA_HOME/labsecurity (default ~/.local/share), $XDG_CONFIG_HOME/labsecurity
#                       (~/.config), $XDG_CACHE_HOME/labsecurity (~/.cache), $XDG_STATE_HOME/labsecurity (~/.local/state)
#
# Sets LABSEC_DATA_DIR, LABSEC_CONFIG_DIR, LABSEC_CACHE_DIR and LABSEC_STATE_DIR, keeping any value already exported.

_labsec_xdg() { # variable value, fallback relative to $HOME: an absolute XDG path wins, anything else is ignored
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$HOME" "$2" ;;
  esac
}

labsec_resolve_paths() {
  local lab_home="${LABSEC_HOME:-}" base="" data config cache state
  # shellcheck disable=SC2088 # the patterns are the literal text ~ and ~/ typed by the user
  case "$lab_home" in
    '~') lab_home="$HOME" ;;
    '~/'*) lab_home="$HOME/${lab_home#\~/}" ;;
  esac
  if [ -n "$lab_home" ]; then
    base="$lab_home"
  elif [ "$(uname -s)" = "Darwin" ]; then
    base="$HOME/Library/Application Support/LabSecurity"
  fi
  if [ -n "$base" ]; then
    data="$base"; config="$base/config"; cache="$base/cache"; state="$base/state"
  else
    data="$(_labsec_xdg "${XDG_DATA_HOME:-}" .local/share)/labsecurity"
    config="$(_labsec_xdg "${XDG_CONFIG_HOME:-}" .config)/labsecurity"
    cache="$(_labsec_xdg "${XDG_CACHE_HOME:-}" .cache)/labsecurity"
    state="$(_labsec_xdg "${XDG_STATE_HOME:-}" .local/state)/labsecurity"
  fi
  LABSEC_DATA_DIR="${LABSEC_DATA_DIR:-$data}"
  LABSEC_CONFIG_DIR="${LABSEC_CONFIG_DIR:-$config}"
  LABSEC_CACHE_DIR="${LABSEC_CACHE_DIR:-$cache}"
  LABSEC_STATE_DIR="${LABSEC_STATE_DIR:-$state}"
}
