#!/usr/bin/env bash
#
# Installation script gets latest mkcert release for platform and makes runnable binary.
#
# This script is meant for quick & easy install via:
#
#   'bash <(curl -sSL https://git.io/mkcert)'
#
# or:
#
#   'bash <(wget -qO- https://git.io/mkcert) --install-dir=/usr/local/bin'
#
# By default, this installs 'mkcert' to current directory.
# If necessary, change destination directory:
#
#   'bash <(curl -sSL https://git.io/mkcert) --install-dir=/usr/local/bin'
#
# Make pull requests at:
# https://github.com/FiloSottile/mkcert/blob/master/get.sh
#

set -o errexit
set -o pipefail

EX_OK=0
EX_ERROR=1
EX_WARNING=2

repository="FiloSottile/mkcert"
installDir=$(pwd)

usage() {
cat << EOF
Installation script gets latest mkcert release for platform and makes runnable binary

Run options:

    -d, --debug	             debug and trace mode
    --install-dir="pwd"      accepts a target installation directory
    -h, --help               display this help and exit
EOF
}

fail() {
	msg=$1
	echo "Error: $msg" 1>&2
	exit ${EX_ERROR}
}

download() {
	url=${1}
	if cmd=$(command -v curl); then
		cmd="$cmd --fail --silent --location"
	elif cmd=$(command -v wget); then
		cmd="$cmd --quiet --output-document=-"
	else
		fail "Require wget or curl are installed"
	fi

	${cmd} "$url"
}

platform() {
	ext=""
	case $(uname -s) in
		Darwin)
			os="macos"
		;;
		Linux)
			os="linux"
		;;
		Windows)
			os="windows"
			ext=".exe"
		;;
		*) fail "Unsupported OS: $(uname -s)";;
	esac

	arch="amd64"
	if ! uname -m | grep 64 > /dev/null; then
		fail "Only arch x64 is currently supported. Your arch is: $(uname -m)"
	fi

	printf "%s" "$os-$arch$ext"
}

option() {
	while [[ -n "$1" ]]; do

		option="$1"

		case $option in
			--install-dir=*)
				installDir="${option#*=}"
				;;
			-d | --debug)
				set -o xtrace
				;;
			-h | --help)
				usage
				exit ${EX_OK}
				;;
			*)
				echo "Unknown option: ${option}"
				usage
				exit ${EX_WARNING}
				;;
		esac
		shift # past argument
	done
}

main() {
	option "$@"
	latest=$(download "https://api.github.com/repos/$repository/releases/latest" | grep tag_name | head -n 1 | cut -d '"' -f 4)
	file="mkcert-$latest-$(platform)"
	path="$installDir/mkcert"
	printf "%s" "Download $latest into $path..."
	download "https://github.com/$repository/releases/download/$latest/$file" > "$path"
	chmod +x "$path"
	printf "DONE\n"
}

main "$@"
