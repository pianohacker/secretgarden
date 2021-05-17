function _kill_ssh_agents {
	jobs -l | grep ssh-agent | awk '{print $2}' | xargs --no-run-if-empty kill
}

function spawn_ssh_agent() {
	unset SSH_AUTH_SOCK
	export SSH_AUTH_SOCK=/tmp/ssh_auth_sock-$$-$RANDOM
	ssh-agent -a $SSH_AUTH_SOCK -D & > /dev/null

	until ssh-add -D >/dev/null 2>&1; do
		sleep .05s
	done
}
