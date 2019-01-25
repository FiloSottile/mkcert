#!/usr/bin/env bash
#
# Script gets latest mkcert release for platform and makes runnable binary.
# By default verification gpg signature todo-url-mkcert.asc.
# This script is meant for quick & easy gets via:
#
#   'gpg --import mkcert.asc'
#   'bash <(curl -sSL https://raw.githubusercontent.com/FiloSottile/mkcert/master/get.sh)'
#
# or:
#
#   'bash <(wget -qO- https://raw.githubusercontent.com/FiloSottile/mkcert/master/get.sh)'
#
# or:
#
#   'bash <(curl -sSL https://git.io/mkcert)'
#
# By default, this script saved 'mkcert' to current directory.
# If necessary, change destination directory:
#
#   'bash <(curl -sSL https://git.io/mkcert) --install-dir=/usr/local/bin'
#
# Make pull requests at:
#
# https://github.com/FiloSottile/mkcert/blob/master/get.sh
#

EX_OK=0
EX_ERROR=1
EX_WARNING=2

repository="FiloSottile/mkcert"

verifySignature=true
installDir=$(pwd)

usage() {
	cat <<EOF
Script gets latest mkcert release for platform and makes runnable binary

Run options:

    -d, --debug	                 debug and trace mode
    -n, --no-verify-signature    skip verify signature
    -i, --install-dir="pwd"      accepts a target installation directory
    -h, --help                   display this help and exit
EOF
}

fail() {
	set -o errexit
	msg=$1
	printf "Error: %s\n" "$msg" 1>&2
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

verify() {
	filePath=${1}
	signaturePath=${2}

	if ! cmd=$(command -v gpg); then
		fail "Require gpg are installed"
	fi

	status=$(${cmd} --status-fd 1 --verify "$signaturePath" "$filePath" 2>/dev/null | grep "^\[GNUPG:\]")

	if ! printf "%s" "$status" | grep --quiet --no-messages "GOODSIG"; then
		fail "$status"
	fi
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
	*) fail "Unsupported OS: $(uname -s)" ;;
	esac

	arch="amd64"
	if ! uname -m | grep 64 >/dev/null; then
		fail "Only arch x64 is currently supported. Your arch is: $(uname -m)"
	fi

	printf "%s" "$os-$arch$ext"
}

option() {
	while [[ -n "$1" ]]; do

		option="$1"

		case ${option} in
		-d | --debug)
			set -o xtrace
			;;
		-i=* | --install-dir=*)
			installDir="${option#*=}"
			;;
		-n | --no-verify-signature)
			verifySignature=false
			;;
		-h | --help)
			usage
			exit ${EX_OK}
			;;
		*)
			printf "Unknown option: %s" "$option"
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
	signature="$file.sig"
	path="$installDir/mkcert"

	printf "Download file: %s" "$file"
	download "https://github.com/$repository/releases/download/$latest/$file" >"$file"

	if "$verifySignature" = true; then
		printf " signature is"
		download "https://github.com/$repository/releases/download/$latest/$signature" >"$signature"
		verify "$file" "$signature"
		rm -f "$signature"
		printf " valid"
	fi

	printf " DONE\n"

	mv "$file" "$path"
	chmod +x "$path"
	printf "Made runnable binary %s DONE\n" "$path"
}

main "$@"
