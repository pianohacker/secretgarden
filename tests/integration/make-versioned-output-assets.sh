#!/bin/bash

set -euo pipefail

script_dir="$(cd $(dirname $BASH_SOURCE[0]); echo $PWD)"
root_dir="$(cd $script_dir/../..; echo $PWD)"

source $script_dir/functions.sh

cd $root_dir
cargo build --release
SECRETGARDEN=$root_dir/target/release/secretgarden

secretgarden_version="$(
	cargo metadata --manifest-path $root_dir/Cargo.toml --format-version 1 | \
		jq -r '.packages[] | select(.name == "secretgarden") | .version'
)"

if [[ -z $secretgarden_version ]]; then
	echo "Failed to determine secretgarden version" >&2
	exit 1
fi

version_assets_directory="$script_dir/assets/versions"

cd "$(mktemp -d)"
mkdir -p $secretgarden_version/outputs
pushd $secretgarden_version

spawn_ssh_agent
trap _kill_ssh_agents EXIT

ssh-keygen -t ed25519 -N '' -C "secretgarden_assets_$secretgarden_version" -f $PWD/id > /dev/null
ssh-add $PWD/id > /dev/null

function store_output {
	$SECRETGARDEN "$@" > outputs/"$*"
}

function store_ssh_key_output {
	store_output "$@"
	store_output "$@" --public
}

cat > secretgarden.toml <<EOF
ssh-key.ssh-key-rsa.type = 'rsa'
ssh-key.ssh-key-dsa.type = 'dsa'
ssh-key.ssh-key-ecdsa.type = 'ecdsa'
ssh-key.ssh-key-ed25519.type = 'ed-25519'
EOF

store_output password password-default
store_ssh_key_output ssh-key ssh-key-default
store_ssh_key_output ssh-key ssh-key-rsa
store_ssh_key_output ssh-key ssh-key-dsa
store_ssh_key_output ssh-key ssh-key-ecdsa
store_ssh_key_output ssh-key ssh-key-ed25519
$SECRETGARDEN set-opaque opaque simple-opaque
store_output opaque opaque
echo simple-opaque | $SECRETGARDEN set-opaque opaque-stdin
store_output opaque opaque-stdin
$SECRETGARDEN set-opaque opaque-base64 --base64 c2ltcGxlLW9wYXF1ZTY0
store_output opaque opaque-base64
echo c2ltcGxlLW9wYXF1ZTY0 | $SECRETGARDEN set-opaque opaque-base64-stdin --base64
store_output opaque opaque-base64-stdin
store_output x509 certificate

popd

tar cJvf ${secretgarden_version}.tar.xz $secretgarden_version
mv ${secretgarden_version}.tar.xz $version_assets_directory/
