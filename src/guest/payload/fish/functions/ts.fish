function ts --description 'Attach to or create an administrative tmux session'
    set -l session admin
    if test (count $argv) -gt 0
        set session $argv[1]
    end
    if set -q TMUX
        tmux has-session -t "$session" 2>/dev/null; or tmux new-session -d -s "$session"
        tmux switch-client -t "$session"
    else
        tmux new-session -A -s "$session"
    end
end
