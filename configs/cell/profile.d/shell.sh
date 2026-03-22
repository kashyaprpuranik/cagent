# History
export HISTFILE="$HOME/.bash_history"
export HISTSIZE=1000
export HISTFILESIZE=2000
export HISTCONTROL=ignoreboth
shopt -s histappend

# Color prompt: user@host:cwd$
if [ "$(id -u)" -eq 0 ]; then
    PS1='\[\e[1;31m\]\u\[\e[0m\]@\[\e[1;34m\]\h\[\e[0m\]:\[\e[1;32m\]\w\[\e[0m\]# '
else
    PS1='\[\e[1;36m\]\u\[\e[0m\]@\[\e[1;34m\]\h\[\e[0m\]:\[\e[1;32m\]\w\[\e[0m\]$ '
fi

# Colors
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

export EDITOR=vim
export PAGER=less
