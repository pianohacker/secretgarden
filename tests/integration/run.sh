#!/bin/bash
#
## License
#
# Copyright (c) 2020 Jesse Weaver.
#
# This file is part of secretgarden.
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

## Setup
# Fail on errors or uninitialized variables,
set -eu
# and propagate up errors in pipes and command substitutions.
set -o pipefail

script_dir="$(cd $(dirname $BASH_SOURCE[0]); echo $PWD)"

source $script_dir/functions.sh

# Save off the location of secretgarden.
SECRETGARDEN="$(cd $(dirname ${BASH_SOURCE[0]}); echo $PWD/secretgarden)"

# Create a temporary directory to run tests in that we'll delete later.
export TEST_FILE="$(realpath ${BASH_SOURCE[0]})"
export TEST_DIR="$(mktemp -d -t secretgarden-tests.XXXXXXXX)"

export RUST_BACKTRACE=1
export RUST_LIB_BACKTRACE=1
if [[ -n ${RUST_NIGHTLY:-} ]]; then
	rustup run nightly cargo build ${CARGO_FLAGS:---release}
else
	cargo build ${CARGO_FLAGS:---release}
fi
SECRETGARDEN=$PWD/target/release/secretgarden

cd $TEST_DIR
trap "rm -rf $TEST_DIR" EXIT

# Create fake gpg, ssh agent
cat > ./gpg <<'EOF'
#!/bin/bash

if [[ "$@" == *--decrypt* ]]; then
	cat secrets.json.gpg
else
	cat
fi
EOF
chmod +x ./gpg
export PATH="$TEST_DIR:$PATH"

## Shared functions
if [[ -t 1 ]]; then
	function _wrap_if_tty() {
		echo "$1$3$2"
	}
else
	function _wrap_if_tty() {
		echo "$3"
	}
fi

function error_text() {
	_wrap_if_tty $'\e[31m' $'\e[0m' "$@"
}

function success_text() {
	_wrap_if_tty $'\e[32m' $'\e[0m' "$@"
}

function skip_text() {
	_wrap_if_tty $'\e[33m' $'\e[0m' "$@"
}

function _assert_failed() {
	echo "assertion failed: $1"

	echo "backtrace:"
	for i in $(seq 1 $(( ${#FUNCNAME[*]} - 1 ))); do
		echo "  ${FUNCNAME[$i]}:${BASH_LINENO[$(( i - 1 ))]}"
	done

	exit 1
}

function assert_equal() {
	if [[ "$1" != "$2" ]]; then
		_assert_failed "'$1' != '$2'" 
	fi
}

function assert_sg_equal() {
	assert_equal "$(secretgarden $1)" "$2"
}

function assert_not_equal() {
	if [[ "$1" == "$2" ]]; then
		_assert_failed "'$1' == '$2'" 
	fi
}

function assert_sg_not_equal() {
	assert_not_equal "$(secretgarden $1)" "$2"
}

function assert_match() {
	if ! [[ "$1" =~ $2 ]]; then
		_assert_failed "'$1' !~ /$2/" 
	fi
}

function assert_sg_match() {
	assert_match "$(secretgarden $1)" "$2"
}

function assert_sg() {
	$SECRETGARDEN $1 || _assert_failed "secretgarden succeeds with flags '$1'"
}

function assert_sg_fails() {
	! $SECRETGARDEN $1 || _assert_failed "secretgarden fails with flags '$1'"
}

function assert_sg_fails_matching() {
	error_text="$(! $SECRETGARDEN $1 2>&1)" || _assert_failed "secretgarden fails with flags '$1'"
	echo $error_text

	assert_match "$error_text" "$2"
}

## Tests
function test_setting_opaque() {
	assert_sg "set-opaque opaque1 opaqueval"
	assert_sg_equal "opaque opaque1" "opaqueval"
}

function test_setting_multiple_opaques_does_not_collide() {
	assert_sg "set-opaque opaque1 opaqueval1"
	assert_sg "set-opaque opaque2 opaqueval2"
	assert_sg_equal "opaque opaque1" "opaqueval1"
	assert_sg_equal "opaque opaque2" "opaqueval2"
}

function test_setting_opaque_from_base64() {
	assert_sg "set-opaque opaque1 --base64 YmFzZTY0dGVzdA=="
	assert_sg_equal "opaque opaque1" "base64test"
	echo 'YmFzZTY0c3RkaW4=' |  assert_sg "set-opaque opaque2 --base64"
	assert_sg_equal "opaque opaque2" "base64stdin"
}

function test_setting_opaque_from_base64_fails_with_concise_error() {
	assert_sg_fails_matching "set-opaque opaque1 --base64 A" '^Error: .* base64'
}

function test_getting_opaque_as_base64() {
	assert_sg "set-opaque opaque1 base64test"
	assert_sg_equal "opaque opaque1 --base64" "YmFzZTY0dGVzdA=="
	echo 'base64stdin' | assert_sg "set-opaque opaque2"
	assert_sg_equal "opaque opaque2 --base64" "YmFzZTY0c3RkaW4="
}

function test_opaque_cannot_be_generated() {
	assert_sg_fails "opaque opaque1"
}

function test_password_generation_options() {
	assert_sg_match "password password1 --length 12" '^.{12}$'
	assert_sg_match "password password2 --length 32" '^.{32}$'
}

function test_password_persists() {
	password="$($SECRETGARDEN password password1 --length 12)"
	assert_match "$password" '^.{12}$'
	assert_sg_equal "password password1 --length 12" "$password"
}

function test_password_converges() {
	password="$($SECRETGARDEN password password1 --length 12)"
	assert_sg_equal "password password1 --length 12" "$password"
	password_converged="$($SECRETGARDEN password password1 --length 13)"
	assert_match "$password_converged" '^.{13}$'
	assert_sg_not_equal "$password_converged" "$password"
}

function test_password_generation_can_be_disabled() {
	assert_sg_fails "password password1 --generate=never"
	assert_sg "password password1"
	assert_sg "password password1 --generate=never"
}

function test_password_convergence_can_be_disabled() {
	password="$($SECRETGARDEN password password1 --length 12)"
	assert_sg_equal "password password1 --length 12" "$password"
	assert_sg_equal "password password1 --generate=once --length 13" "$password"
}

function test_ssh_key_separate_generation() {
	private_key="$($SECRETGARDEN ssh-key key1)"
	public_key="$($SECRETGARDEN ssh-key key1 --public)"

	if ! derived_public_key="$(ssh-keygen -y -f <(echo "$private_key"))"; then
		exit 1
	fi

	assert_equal "$(ssh-keygen -y -f <(echo "$private_key"))" "$public_key"
}

function test_ssh_keys_can_be_generated_with_any_type() {
	# This could be a loop, but SSH key type IDs have a lot of subtle variation...
	assert_match "$($SECRETGARDEN ssh-key key-rsa --public --type rsa)" "^ssh-rsa "
	assert_match "$($SECRETGARDEN ssh-key key-dsa --public --type dsa)" "^ssh-dss "
	assert_match "$($SECRETGARDEN ssh-key key-ecdsa --public --type ecdsa)" "^ecdsa-sha2-nistp256 "
	assert_match "$($SECRETGARDEN ssh-key key-ed-25519 --public --type ed-25519)" "^ssh-ed25519 "
}

function _assert_ssh_key_bits() {
	assert_match "$(ssh-keygen -lf <(echo "$1"))" "^$2 "
}

function test_ssh_keys_can_be_generated_with_custom_bits() {
	_assert_ssh_key_bits "$($SECRETGARDEN ssh-key key-rsa --public --type rsa --bits 4096)" 4096
	_assert_ssh_key_bits "$($SECRETGARDEN ssh-key key-ecdsa --public --type ecdsa --bits 521)" 521
}

function test_ssh_key_types_with_fixed_lengths_reject_custom_bits() {
	assert_sg "ssh-key key-ed25519 --type ed-25519"
	assert_sg_fails "ssh-key key-ed25519-256 --type ed-25519 --bits 256"

	assert_sg "ssh-key key-dsa --type dsa"
	assert_sg_fails "ssh-key key-dsa-2048 --type dsa --bits 2048"
}

function test_values_not_stored_in_plaintext() {
	assert_sg "set-opaque opaque1 opaqueval"

	! grep opaqueval secret*
}

function test_encrypted_container_different_each_time() {
	assert_sg "set-opaque opaque1 opaqueval"
	first_sha256sum="$(sha256sum secretgarden.dat | cut -d ' ' -f 1)"
	rm secretgarden.dat

	assert_sg "set-opaque opaque1 opaqueval"
	second_sha256sum="$(sha256sum secretgarden.dat | cut -d ' ' -f 1)"

	assert_not_equal "$first_sha256sum" "$second_sha256sum"
}

function test_values_cannot_be_decrypted_with_different_ssh_key() {
	assert_sg "set-opaque opaque1 opaqueval"
	assert_sg_equal "opaque opaque1" "opaqueval"

	spawn_ssh_agent
	ssh-keygen -t ed25519 -N '' -f $PWD/id2
	ssh-add $PWD/id2

	assert_sg_fails_matching "opaque opaque1" "$(ssh-keygen -l -f $PWD/orig-id | cut -d ' ' -f 2 | sed -e 's,+,\\+,g')"
}

function test_values_can_be_decrypted_regardless_of_ssh_key_order() {
	assert_sg "set-opaque opaque1 opaqueval"
	assert_sg_equal "opaque opaque1" "opaqueval"

	spawn_ssh_agent
	ssh-keygen -t ed25519 -N '' -f $PWD/id2
	ssh-add $PWD/id2
	ssh-add $PWD/orig-id

	assert_sg "opaque opaque1"
}

function test_values_can_be_decrypted_with_each_ssh_key_type() {
	for key_type in rsa ed25519; do
		spawn_ssh_agent
		ssh-keygen -t $key_type -N '' -f $PWD/id-$key_type
		ssh-add $PWD/id-$key_type

		assert_sg "set-opaque opaque1 opaqueval"
		assert_sg_equal "opaque opaque1" "opaqueval"

		rm secretgarden.dat
	done
}

function test_encryption_fails_if_only_ssh_key_types_with_randomized_signatures_are_available() {
	for key_type in dsa ecdsa; do
		spawn_ssh_agent
		ssh-keygen -t $key_type -N '' -f $PWD/id-$key_type
		ssh-add $PWD/id-$key_type

		rm -f secretgarden.dat
		assert_sg_fails "set-opaque opaque1 opaqueval"
	done
}

function test_encryption_selects_ssh_key_types_with_deterministic_signatures() {
	for key_type in dsa ecdsa; do
		spawn_ssh_agent
		ssh-keygen -t $key_type -N '' -f $PWD/id-$key_type
		ssh-add $PWD/id-$key_type
		ssh-add $PWD/orig-id

		assert_sg "set-opaque opaque1 opaqueval"
		assert_sg "opaque opaque1"

		ssh-add -d $PWD/orig-id.pub
		assert_sg_fails_matching "opaque opaque1" "fingerprint"
	done
}

function test_output_compatible_with_previous_versions() {
	set -x 
	IFS=$'\n'

	for version_archive in $script_dir/assets/versions/*.tar.xz; do
		tar xf $version_archive
		pushd $(basename ${version_archive%%.tar.*})

		ssh-add -D
		ssh-add id

		for output in $(cd outputs; ls); do
			diff -u outputs/"$output" <(eval "$SECRETGARDEN $output") || exit 1
		done

		popd
	done
}

## Test running loop
function get_test_functions() {
	awk '/^function test_/ { print $2 }' "${TEST_FILE}" | sed -e 's/()//'
}

# If any test functions are named FOCUS, default to focusing those.
if get_test_functions | grep FOCUS; then
	: ${FOCUS:=FOCUS}
fi

focus_filter=${FOCUS:-'^.*$'}

## Test running loop
for test_function in $(awk '/^function test_/ { print $2 }' "${TEST_FILE}" | sed -e 's/()//'); do
	test_name="$(sed -e 's/^test_//;s/_/ /g' <<<"$test_function")"

	if ! [[ "$test_name" =~ $focus_filter ]]; then
		echo "$(skip_text '[SKIP]') $test_name"
		continue
	fi

	if result=$(
		cd "$(TMPDIR=$TEST_DIR mktemp -d -t $test_function.XXXXXXXX)"

		spawn_ssh_agent
		trap _kill_ssh_agents EXIT
		ssh-keygen -t ed25519 -N '' -f $PWD/orig-id > /dev/null
		ssh-add -q $PWD/orig-id > /dev/null

		exec 2>&1
		$test_function

		_kill_ssh_agents
	); then
		echo "$(success_text '[OK]') $test_name" 

		if [[ ${TEST_VERBOSITY:-} -ge 1 ]]; then
			echo "$result" | sed -e 's/^/    /'
		fi
	else
		echo "$(error_text '[FAILED]') $test_name"
		if [[ ${TEST_VERBOSITY:-} -ge 0 ]]; then
			echo "$result" | sed -e 's/^/    /'
		fi
		if [[ -z ${KEEP_GOING:-} ]]; then
			exit 1
		fi
	fi
done
