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

# Save off the location of secretgarden.
SECRETGARDEN="$(cd $(dirname ${BASH_SOURCE[0]}); echo $PWD/secretgarden)"

# Create a temporary directory to run tests in that we'll delete later.
export TEST_FILE="$(realpath ${BASH_SOURCE[0]})"
export TEST_DIR="$(mktemp -d)"
cd $TEST_DIR
trap "rm -rf $TEST_DIR" exit

# Create fake gpg.
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

function _assert_failed() {
	echo "assertion failed at line ${BASH_LINENO[2]}: $1"
}

function assert_equal() {
	if [[ "$1" != "$2" ]]; then
		_assert_failed "'$1' != '$2'" 
		exit 1
	fi
}

function assert_sg_equal() {
	assert_equal "$(secretgarden $1)" "$2"
}

function assert_not_equal() {
	if [[ "$1" == "$2" ]]; then
		_assert_failed "'$1' == '$2'" 
		exit 1
	fi
}

function assert_sg_not_equal() {
	assert_not_equal "$(secretgarden $1)" "$2"
}

function assert_match() {
	if ! [[ "$1" =~ $2 ]]; then
		_assert_failed "'$1' !~ /$2/" 
		exit 1
	fi
}

function assert_sg_match() {
	assert_match "$(secretgarden $1)" "$2"
}

function assert_sg() {
	$SECRETGARDEN $1 || exit 1
}

function assert_sg_fails() {
	! $SECRETGARDEN $1
}

## Tests
function test_setting_opaque() {
	assert_sg "set opaque opaque1 opaqueval"
	assert_sg_equal "opaque opaque1" "opaqueval"
}

function test_setting_multiple_opaques_does_not_collide() {
	assert_sg "set opaque opaque1 opaqueval1"
	assert_sg "set opaque opaque2 opaqueval2"
	assert_sg_equal "opaque opaque1" "opaqueval1"
	assert_sg_equal "opaque opaque2" "opaqueval2"
}

function test_setting_opaque_from_base64() {
	assert_sg "set opaque opaque1 --base64 YmFzZTY0dGVzdA=="
	assert_sg_equal "opaque opaque1" "base64test"
	echo 'YmFzZTY0c3RkaW4=' |  assert_sg "set opaque opaque2 --base64"
	assert_sg_equal "opaque opaque2" "base64stdin"
}

function test_getting_opaque_as_base64() {
	assert_sg "set opaque opaque1 base64test"
	assert_sg_equal "opaque opaque1 --base64" "YmFzZTY0dGVzdA=="
	echo 'base64stdin' | assert_sg "set opaque opaque2"
	assert_sg_equal "opaque opaque2 --base64" "YmFzZTY0c3RkaW4="
}

function test_opaque_cannot_be_generated() {
	assert_sg_fails "opaque opaque1"
}

function test_password_persists() {
	password="$($SECRETGARDEN password password1 --length 12)"
	assert_match "$password" ".{12}"
	assert_sg_equal "password password1 --length 12" "$password"
}

function test_password_converges() {
	password="$($SECRETGARDEN password password1 --length 12)"
	assert_sg_equal "password password1 --length 12" "$password"
	assert_sg_not_equal "password password1 --length 13" "$password"
}

function test_password_generation_can_be_disabled() {
	assert_sg_fails "password password1 --generate=no"
}

function test_password_convergence_can_be_disabled() {
	password="$($SECRETGARDEN password password1 --length 12)"
	assert_sg_equal "password password1 --length 12" "$password"
	assert_sg_equal "password password1 --generate=once --length 13" "$password"
}

## Test running loop
for test_function in $(awk '/^function test_/ { print $2 }' "${TEST_FILE}" | sed -e 's/()//'); do
	test_name="$(sed -e 's/^test_//;s/_/ /g' <<<"$test_function")"

	if result=$(cd "$(mktemp -d -p $TEST_DIR)"; exec 2>&1; $test_function); then
		echo "$(success_text '[OK]') $test_name" 

		if [[ -n ${TEST_VERBOSE:-} ]]; then
			echo "$result" | sed -e 's/^/    /'
		fi
	else
		echo "$(error_text '[FAILED]') $test_name"
		echo "$result" | sed -e 's/^/    /'
		exit 1
	fi
done
