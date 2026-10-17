# artoo guest baseline shell — fish 4.x
# Shared provisioning payload: secret-free, Mac-independent, no histories.
set -gx EDITOR vim
set -gx VISUAL vim
set -gx LANG en_US.UTF-8

fish_add_path $HOME/.local/bin

if not status is-interactive
    return
end

set -g fish_greeting ""
fish_default_key_bindings

# History: on, in $XDG_DATA_HOME/fish/fish_history (fish 4 default).
# fish has no HISTFILE variable. Built-in hygiene: commands quoted with a
# leading space are never recorded — use that for anything secret-adjacent.
set -g fish_cursor_default block
set -g fish_cursor_insert block

# ---- Gruvbox palette (shared constants for prompt/UI anything scripting) ----
set -g gruvbox_red    fb4934
set -g gruvbox_green  b8bb26
set -g gruvbox_yellow fabd2f
set -g gruvbox_blue   83a598
set -g gruvbox_purple d3869b
set -g gruvbox_aqua   8ec07c
set -g gruvbox_orange fe8019

# ---- Fish UI colors (Gruvbox) ----
set -g fish_color_normal         ebdbb2
set -g fish_color_command        8ec07c
set -g fish_color_error          fb4934
set -g fish_color_end            fe8019
set -g fish_color_param          ebdbb2
set -g fish_color_quote          fabd2f
set -g fish_color_redirection    83a598
set -g fish_color_operator       83a598
set -g fish_color_escape         d3869b
set -g fish_color_autosuggestion 928374
set -g fish_color_selection      '--background=3c3836'
set -g fish_color_search_match   '--background=3c3836' fabd2f
set -g fish_pager_color_prefix      fe8019
set -g fish_pager_color_description bdae93
set -g fish_pager_color_progress    '--background=3c3836'

# ---- Tool integrations (guarded: each stays optional) ----
if type -q starship
    starship init fish | source
end
if type -q zoxide
    zoxide init fish | source
    alias cd='z'
end
if type -q fzf
    set -gx FZF_DEFAULT_OPTS "--height 40% --layout=reverse --border --info=inline"
    fzf --fish | source
end
if type -q eza
    alias l  'eza -la --group-directories-first'
    alias ll 'eza -la --group-directories-first'
    alias lt 'eza --tree --level=2 --group-directories-first'
end

# Safe interactive file operations (mirrors the workstation muscle memory);
# automation paths run Bash via SSH and are unaffected.
function cp_safe; command cp -iv $argv; end
function mv_safe; command mv -iv $argv; end
function rm_safe; command rm -iv $argv; end
alias cp='cp_safe'
alias mv='mv_safe'
alias rm='rm_safe'

abbr -a gst  'git status'
abbr -a glog 'git log --oneline --graph --decorate'
abbr -a gd   'git diff'
abbr -a conns 'ports -c'
