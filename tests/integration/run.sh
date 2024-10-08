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

## Shared functions
if [[ -t 1 || -n ${FORCE_COLOR:-} ]]; then
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
		_assert_failed "(received == expected) '$1' == '$2'" 
	fi
}

function assert_sg_equal() {
	local value="$1"; shift
	assert_equal "$($SECRETGARDEN "$@")" "$value"
}

function assert_not_equal() {
	if [[ "$1" == "$2" ]]; then
		_assert_failed "(received != expected) '$1' != '$2'" 
	fi
}

function assert_match() {
	if ! [[ "$1" =~ $2 ]]; then
		_assert_failed "(received =~ /pattern/) '$1' =~ /$2/" 
	fi
}

function assert_no_match() {
	if [[ "$1" =~ $2 ]]; then
		_assert_failed "(received !~ /pattern/) '$1' !~ /$2/" 
	fi
}

function assert_sg_match() {
	local value="$1"; shift
	assert_match "$($SECRETGARDEN "$@")" "$value"
}

function assert_sg() {
	$SECRETGARDEN "$@" || _assert_failed "secretgarden succeeds with flags '$@'"
}

function assert_sg_fails_matching() {
	local pattern="$1"; shift
	error_text="$(! $SECRETGARDEN "$@" 2>&1)" || _assert_failed "secretgarden fails with flags '$1'"
	echo $error_text

	assert_match "$error_text" "$pattern"
}

function config() {
	touch secretgarden.toml
	if grep "$1" secretgarden.toml; then
		sed -i -e '/'$1'/{s/.*/'$1'='$2'/}' secretgarden.toml
	else
		echo "$1=$2" >> secretgarden.toml
	fi
}

## Tests
function test_setting_opaque() {
	assert_sg set-opaque opaque1 opaqueval
	assert_sg_equal "opaqueval" opaque opaque1
}

function test_setting_multiple_opaques_does_not_collide() {
	assert_sg set-opaque opaque1 opaqueval1
	assert_sg set-opaque opaque2 opaqueval2
	assert_sg_equal "opaqueval1" opaque opaque1
	assert_sg_equal "opaqueval2" opaque opaque2
}

function test_setting_opaque_from_base64() {
	assert_sg set-opaque opaque1 --base64 YmFzZTY0dGVzdA==
	assert_sg_equal "base64test" opaque opaque1
	echo 'YmFzZTY0c3RkaW4=' |  assert_sg set-opaque opaque2 --base64
	assert_sg_equal "base64stdin" opaque opaque2
}

function test_setting_opaque_from_base64_fails_with_concise_error() {
	echo '!' | assert_sg_fails_matching " '^Error: .* base64' " set-opaque opaque1 --base64 
}

function test_getting_opaque_as_base64() {
	assert_sg set-opaque opaque1 base64test
	assert_sg_equal "YmFzZTY0dGVzdA==" opaque opaque1 --base64
	echo 'base64stdin' | assert_sg set-opaque opaque2
	assert_sg_equal "YmFzZTY0c3RkaW4=" opaque opaque2 --base64
}

function test_opaque_cannot_be_generated() {
	assert_sg_fails_matching "Cannot generate" opaque opaque1
}

function test_password_generation_options() {
	config password.password1.length 12
	assert_sg_match '^.{12}$' password password1
	config password.password2.length 32
	assert_sg_match '^.{32}$' password password2
}

function test_password_persists() {
	config password.password1.length 12
	password="$($SECRETGARDEN password password1)"
	assert_match "$password" '^.{12}$'
	assert_sg_equal "$password" password password1
}

function test_password_converges() {
	config password.password1.length 12
	password="$($SECRETGARDEN password password1)"
	assert_sg_equal "$password" password password1
	config password.password1.length 13
	password_converged="$($SECRETGARDEN password password1)"
	assert_match "$password_converged" '^.{13}$'
	assert_not_equal "$password_converged" "$password"
}

function test_password_generation_can_be_disabled() {
	assert_sg_fails_matching "does not exist" password password1 --generate=never
	assert_sg password password1
	assert_sg password password1 --generate=never
}

function test_password_convergence_can_be_disabled() {
	config password.password1.length 12
	assert_sg password password1 > password1
	assert_sg_equal "$(cat password1)" password password1
	config password.password1.length 13
	assert_sg_equal "$(cat password1)" password password1 --generate=once
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
	config ssh-key.key-rsa.type "'rsa'"
	assert_match "$($SECRETGARDEN ssh-key key-rsa --public)" "^[^ ]*rsa[^ ]* "
	config ssh-key.key-dsa.type "'dsa'"
	assert_match "$($SECRETGARDEN ssh-key key-dsa --public)" "^[^ ]*dss[^ ]* "
	config ssh-key.key-ecdsa.type "'ecdsa'"
	assert_match "$($SECRETGARDEN ssh-key key-ecdsa --public)" "^[^ ]*ecdsa[^ ]* "
	config ssh-key.key-ed25519.type "'rsa'"
	assert_match "$($SECRETGARDEN ssh-key key-ed-25519 --public)" "^[^ ]*ed25519[^ ]* "
}

function _assert_ssh_key_bits() {
	assert_match "$(ssh-keygen -lf <(echo "$1"))" "^$2 "
}

function test_ssh_keys_can_be_generated_with_custom_bits() {
	config ssh-key.key-rsa.type "'rsa'"
	config ssh-key.key-rsa.bits 4096
	config ssh-key.key-ecdsa.type "'ecdsa'"
	config ssh-key.key-ecdsa.bits 521
	_assert_ssh_key_bits "$($SECRETGARDEN ssh-key key-rsa --public)" 4096
	_assert_ssh_key_bits "$($SECRETGARDEN ssh-key key-ecdsa --public)" 521
}

function test_ssh_key_types_with_fixed_lengths_reject_custom_bits() {
	config ssh-key.key-ed25519.type "'ed-25519'"
	assert_sg ssh-key key-ed25519
	config ssh-key.key-ed25519-256.type "'ed-25519'"
	config ssh-key.key-ed25519-256.bits 256
	assert_sg_fails_matching "cannot be specified" ssh-key key-ed25519-256

	config ssh-key.key-dsa.type "'dsa'"
	assert_sg ssh-key key-dsa
	config ssh-key.key-dsa-2048.type "'dsa'"
	config ssh-key.key-dsa-2048.bits 2048
	assert_sg_fails_matching "only have 1024 bits" ssh-key key-dsa-2048
}

function test_values_not_stored_in_plaintext() {
	assert_sg set-opaque opaque1 opaqueval

	! grep opaqueval secret*
}

function test_encrypted_container_different_each_time() {
	assert_sg set-opaque opaque1 opaqueval
	first_sha256sum="$(sha256sum secretgarden.dat | cut -d ' ' -f 1)"
	rm secretgarden.dat

	assert_sg set-opaque opaque1 opaqueval
	second_sha256sum="$(sha256sum secretgarden.dat | cut -d ' ' -f 1)"

	assert_not_equal "$first_sha256sum" "$second_sha256sum"
}

function test_values_cannot_be_decrypted_with_different_ssh_key() {
	assert_sg set-opaque opaque1 opaqueval
	assert_sg_equal "opaqueval" opaque opaque1

	spawn_ssh_agent
	ssh-keygen -t ed25519 -N '' -f $PWD/id2
	ssh-add $PWD/id2

	assert_sg_fails_matching "$(ssh-keygen -l -f $PWD/orig-id | cut -d ' ' -f 2 | sed -e 's,+,\\+,g')" opaque opaque1
}

function test_values_can_be_decrypted_regardless_of_ssh_key_order() {
	assert_sg set-opaque opaque1 opaqueval
	assert_sg_equal "opaqueval" opaque opaque1

	spawn_ssh_agent
	ssh-keygen -t ed25519 -N '' -f $PWD/id2
	ssh-add $PWD/id2
	ssh-add $PWD/orig-id

	assert_sg opaque opaque1
}

function test_values_can_be_decrypted_with_each_ssh_key_type() {
	for key_type in rsa ed25519; do
		spawn_ssh_agent
		ssh-keygen -t $key_type -N '' -f $PWD/id-$key_type
		ssh-add $PWD/id-$key_type

		assert_sg set-opaque opaque1 opaqueval
		assert_sg_equal "opaqueval" opaque opaque1

		rm secretgarden.dat
	done
}

function test_encryption_fails_if_only_ssh_key_types_with_randomized_signatures_are_available() {
	for key_type in dsa ecdsa; do
		spawn_ssh_agent
		ssh-keygen -t $key_type -N '' -f $PWD/id-$key_type
		ssh-add $PWD/id-$key_type

		rm -f secretgarden.dat
		assert_sg_fails_matching "No valid keys" set-opaque opaque1 opaqueval
	done
}

function test_encryption_selects_ssh_key_types_with_deterministic_signatures() {
	for key_type in dsa ecdsa; do
		spawn_ssh_agent
		ssh-keygen -t $key_type -N '' -f $PWD/id-$key_type
		ssh-add $PWD/id-$key_type
		ssh-add $PWD/orig-id

		assert_sg set-opaque opaque1 opaqueval
		assert_sg opaque opaque1

		ssh-add -d $PWD/orig-id.pub
		assert_sg_fails_matching "fingerprint" opaque opaque1
	done
}

function test_x509_generates_valid_certificates() {
	assert_sg x509 cert1 > cert.pem
	openssl x509 -noout < cert.pem || _assert_failed "x509 result was valid"
}

function test_x509_generates_valid_private_keys() {
	assert_sg x509 cert1 > cert.pem
	openssl pkey -noout -check < cert.pem || _assert_failed "RSA result was valid"
}

function test_x509_subject_and_issuer_default_to_secret_name() {
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -subject < cert.pem)" "subject=CN *= *cert1"
	assert_match "$(openssl x509 -noout -issuer < cert.pem)" "issuer=CN *= *cert1"
}

function test_x509_not_before_and_not_before_default_to_a_year_apart() {
	assert_sg x509 cert1 > cert.pem
	today="$(LC_ALL=C TZ=UTC date +"%b %e.*%Y.*")"
	one_year="$(LC_ALL=C TZ=UTC date +"%b %e.*%Y.*" -d "365 days")"
	assert_match "$(LC_ALL=C openssl x509 -noout -dates < cert.pem)" "notBefore=$today"$'\n'"notAfter=$one_year"
}

function test_x509_can_adjust_duration() {
	config x509.cert1.duration-days 52
	assert_sg x509 cert1 > cert.pem
	today="$(LC_ALL=C TZ=UTC date +"%b %e.*%Y.*")"
	fifty_two_days="$(LC_ALL=C TZ=UTC date +"%b %e.*%Y.*" -d "52 days")"
	assert_match "$(LC_ALL=C openssl x509 -noout -dates < cert.pem)" "notBefore=$today"$'\n'"notAfter=$fifty_two_days"
}

function test_x509_regenerates_when_expired() {
	config x509.cert1.duration-days 1
	assert_sg x509 cert1 > cert1a.pem
	SECRETGARDEN="faketime -f +2s $SECRETGARDEN" assert_sg x509 cert1 > cert1b.pem
	diff cert1a.pem cert1b.pem > /dev/null || _assert_failed "unexpired certificate should not regenerate"

	config x509.cert2.duration-days 0
	assert_sg x509 cert2 > cert2a.pem
	SECRETGARDEN="faketime -f +2s $SECRETGARDEN" assert_sg x509 cert2 > cert2b.pem

	diff cert2a.pem cert2b.pem > /dev/null && _assert_failed "expired certificate should regenerate"
}

function test_x509_outputs_certificate_and_private_key_by_default() {
	assert_sg x509 cert1 > cert.pem
	assert_match "$(cat cert.pem)" "BEGIN CERTIFICATE"
	assert_match "$(cat cert.pem)" "BEGIN PRIVATE KEY"
}

function test_x509_can_output_certificate_only() {
	assert_sg x509 --certificate cert1 > cert.pem
	openssl x509 -noout < cert.pem || _assert_failed "x509 result was valid"
	assert_no_match "$(cat cert.pem)" "BEGIN PRIVATE KEY"
}

function test_x509_can_output_private_key_only() {
	assert_sg x509 --private-key cert1 > cert.pem
	assert_no_match "$(cat cert.pem)" "BEGIN CERTIFICATE"
	assert_match "$(cat cert.pem)" "BEGIN PRIVATE KEY"
	openssl pkey -noout -check < cert.pem || _assert_failed "RSA result was valid"
}

function test_x509_outputs_both_when_asked_for_certificate_and_private_key() {
	assert_sg x509 --certificate --private-key cert1 > cert.pem
	openssl x509 -noout < cert.pem || _assert_failed "x509 result was valid"
	openssl rsa -noout -check < cert.pem || _assert_failed "RSA result was valid"
}

function test_x509_can_output_public_key_only() {
	assert_sg x509 --public-key cert1 > cert.pem
	assert_no_match "$(cat cert.pem)" "BEGIN CERTIFICATE"
	assert_match "$(cat cert.pem)" "BEGIN PUBLIC KEY"
	openssl pkey -pubin -noout < cert.pem || _assert_failed "RSA public result was valid"
}

function test_x509_has_no_sans_by_default() {
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -ext subjectAltName < cert.pem 2>&1)" "No extensions"
}

function test_x509_can_have_dns_sans() {
	config x509.cert1.dns-sans '["host.domain.example"]'
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -ext subjectAltName < cert.pem)" "DNS:host.domain.example"

	config x509.cert2.dns-sans '["host.domain.example", "host.example.domain"]'
	assert_sg x509 cert2 > cert.pem
	assert_match "$(openssl x509 -noout -ext subjectAltName < cert.pem)" "DNS:host.domain.example, DNS:host.example.domain"
}

function test_x509_can_have_ip_sans() {
	config x509.cert1.ip-sans '["127.0.0.1"]'
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -ext subjectAltName < cert.pem)" "IP Address:127.0.0.1"

	config x509.cert2.ip-sans '["127.0.0.1", "ffee::1"]'
	assert_sg x509 cert2 > cert.pem
	assert_match "$(openssl x509 -noout -ext subjectAltName < cert.pem)" "IP Address:127.0.0.1, IP Address:FFEE:0:0:0:0:0:0:1"
}

function test_x509_can_have_mixed_sans() {
	config x509.cert2.dns-sans '["host.domain.example", "host.example.domain"]'
	config x509.cert2.ip-sans '["127.0.0.1", "ffee::1"]'
	assert_sg x509 cert2 > cert.pem
	assert_match "$(openssl x509 -noout -ext subjectAltName < cert.pem)" "DNS:host.domain.example, DNS:host.example.domain, IP Address:127.0.0.1, IP Address:FFEE:0:0:0:0:0:0:1"
}

function test_x509_common_name_can_be_changed() {
	config x509.cert1.common-name "'Common name'"
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -subject < cert.pem)" "subject=CN *= *Common name"
	assert_match "$(openssl x509 -noout -issuer < cert.pem)" "issuer=CN *= *Common name"
}

function test_x509_subject_can_be_changed() {
	config x509.cert1.subject "'CN=Sample Cert, OU=R&D, O=Company Ltd., L=Dublin 4, ST=Dublin, C=IE'"
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -subject < cert.pem)" "subject=CN *= *Sample Cert, OU *= *R&D, O *= *Company Ltd., L *= *Dublin 4, ST *= *Dublin, C *= *IE"
	assert_match "$(openssl x509 -noout -issuer < cert.pem)" "issuer=CN *= *Sample Cert, OU *= *R&D, O *= *Company Ltd., L *= *Dublin 4, ST *= *Dublin, C *= *IE"
}

function test_x509_is_not_a_ca_by_default() {
	assert_sg x509 cert1 > cert.pem
	assert_match "$(openssl x509 -noout -ext basicConstraints < cert.pem 2>&1)" "No extensions"
}

function test_x509_can_be_a_ca() {
	config x509.ca.is-ca true
	assert_sg x509 ca > cert.pem
	assert_match "$(openssl x509 -noout -ext basicConstraints < cert.pem)" "critical
    CA:TRUE"
}

function test_x509_can_create_a_certificate_signed_by_a_ca() {
	config x509.ca.is-ca true
	assert_sg x509 ca --certificate > ca.pem
	config x509.child.ca "'ca'"
	assert_sg x509 child --certificate > child.pem

	assert_match "$(openssl verify -CAfile ca.pem child.pem)" "OK"
	assert_match "$(openssl x509 -noout -issuer < child.pem)" "issuer=CN *= *ca"
}

function test_x509_only_uses_cas_that_are_cas() {
	assert_sg x509 ca
	config x509.child.ca "'ca'"
	assert_sg_fails_matching "CA" x509 child
}

function test_x509_fails_when_ca_expired() {
	config x509.ca.duration-days 0
	config x509.ca.is-ca true
	assert_sg x509 ca > ca1a.pem
	config x509.child.ca "'ca'"
	SECRETGARDEN="faketime -f +2s $SECRETGARDEN" assert_sg_fails_matching "expired" x509 child
}

function test_x509_issuer_correct_for_ca_with_custom_subject() {
	config x509.ca.is-ca true
	config x509.ca.subject "'CN=Sample Cert, OU=R&D, O=Company Ltd., L=Dublin 4, ST=Dublin, C=IE'"
	assert_sg x509 ca > ca.pem
	config x509.child.ca "'ca'"
	assert_sg x509 child > child.pem
	assert_match "$(openssl x509 -noout -subject < child.pem)" "subject=CN *= *child"
	assert_match "$(openssl x509 -noout -issuer < child.pem)" "issuer=CN *= *Sample Cert, OU *= *R&D, O *= *Company Ltd., L *= *Dublin 4, ST *= *Dublin, C *= *IE"
}
function test_x509_rejects_unknown_config() {
	config x509.cert1.duration_days 52
	assert_sg_fails_matching "duration_days" x509 cert1
}

function test_output_compatible_with_previous_versions() {
	IFS=$'\n'

	for version_archive in $(ls -1 "$script_dir/assets/versions/"); do
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

function test_ansible_plugin_can_be_installed {
	export HOME=$PWD/home
	assert_sg install-ansible-plugin

	python3 -m py_compile $HOME/.ansible/plugins/lookup/secretgarden.py || exit 1
}

## Test running loop
function get_test_functions() {
	awk '/^function test_/ { print $2 }' "${TEST_FILE}" | sed -e 's/()//'
}

function run_test_function() {
	local test_function="$1"

	if [[ -z ${INSIDE_RUN_ALL_TESTS:-} ]]; then
		echo "Cannot run tests directly; use FOCUS=..."
		exit 1
	fi

	test_name="$(sed -e 's/^test_//;s/_/ /g' <<<"$test_function")"

	if ! [[ "$test_name" =~ $FOCUS_FILTER ]]; then
		echo "$(skip_text '[SKIP]') $test_name"
		return 0
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
		cd $TEST_DIR
	); then
		echo "$(success_text '[OK]') $test_name" 

		if [[ ${TEST_VERBOSITY:-} -ge 1 ]]; then
			echo "$result" | sed -e 's/^/    /'
		fi

		return 0
	else
		echo "$(error_text '[FAILED]') $test_name"
		if [[ ${TEST_VERBOSITY:-} -ge 0 ]]; then
			echo "$result" | sed -e 's/^/    /'
		fi

		return 1
	fi
}

function run_all_tests() {
	# Save off the location of secretgarden.
	SECRETGARDEN="$(cd $(dirname ${BASH_SOURCE[0]}); echo $PWD/secretgarden)"

	# Create a temporary directory to run tests in that we'll delete later.
	export TEST_FILE="$(realpath ${BASH_SOURCE[0]})"
	export TEST_DIR="$(mktemp -d -t secretgarden-tests.XXXXXXXX)"

	export RUST_BACKTRACE=1
	export RUST_LIB_BACKTRACE=1
	if [[ -n ${RUST_NIGHTLY:-} ]]; then
		rustup run nightly cargo build ${CARGO_FLAGS:---release}
		rustup run nightly cargo test --quiet ${CARGO_FLAGS:---release}
	else
		cargo build ${CARGO_FLAGS:---release}
		cargo test --quiet ${CARGO_FLAGS:---release}
	fi
	export SECRETGARDEN=$PWD/target/release/secretgarden

	cd $TEST_DIR
	trap "rm -rf $TEST_DIR" EXIT

	# If any test functions are named FOCUS, default to focusing those.
	if get_test_functions | grep FOCUS; then
		: ${FOCUS:=FOCUS}
	fi

	export FOCUS_FILTER=${FOCUS:-'^.*$'}

	if [[ -t 1 ]]; then
		export FORCE_COLOR=1
	fi

	## Test running loop
	awk '/^function test_/ { print $2 }' "${TEST_FILE}" | \
		sed -e 's/()//' | \
		INSIDE_RUN_ALL_TESTS=1 xargs -L1 -P $(nproc --ignore=1) $script_dir/run.sh
}

if [[ $# == 1 ]]; then
	if ! run_test_function "$1"; then exit 1; fi
else
	run_all_tests
fi
