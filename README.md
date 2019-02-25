# mkcert

mkcert is a simple tool for making locally-trusted development certificates. It requires no configuration.

```
$ mkcert -install
Created a new local CA at "/Users/filippo/Library/Application Support/mkcert" 💥
The local CA is now installed in the system trust store! ⚡️
The local CA is now installed in the Firefox trust store (requires browser restart)! 🦊

$ mkcert example.com "*.example.org" myapp.dev localhost 127.0.0.1 ::1
Using the local CA at "/Users/filippo/Library/Application Support/mkcert" ✨

Created a new certificate valid for the following names 📜
 - "example.com"
 - "*.example.org"
 - "myapp.dev"
 - "localhost"
 - "127.0.0.1"
 - "::1"

The certificate is at "./example.com+5.crt" and the key at "./example.com+5.key" ✅
```

<p align="center"><img width="498" alt="Chrome and Firefox screenshot" src="https://user-images.githubusercontent.com/1225294/51066373-96d4aa80-15be-11e9-91e2-f4e44a3a4458.png"></p>

Using certificates from real certificate authorities (CAs) for development can be dangerous or impossible (for hosts like `localhost` or `127.0.0.1`), but self-signed certificates cause trust errors. Managing your own CA is the best solution, but usually involves arcane commands, specialized knowledge and manual steps.

mkcert automatically creates and installs a local CA in the system root store, and generates locally-trusted certificates. mkcert does not automatically configure servers to use the certificates, though, that's up to you.

## Installation

> **Warning**: the `rootCA.key` file that mkcert automatically generates gives complete power to intercept secure requests from your machine. Do not share it.

### macOS

On macOS, use [Homebrew](https://brew.sh/)

```
brew install mkcert
brew install nss # if you use Firefox
```

or [MacPorts](https://www.macports.org/).

```
sudo port selfupdate
sudo port install mkcert
sudo port install nss # if you use Firefox
```

### Linux

On Linux, first install `certutil`.

```
sudo apt install libnss3-tools
    -or-
sudo yum install nss-tools
    -or-
sudo pacman -S nss
```

Then you can install using [Linuxbrew](http://linuxbrew.sh/)

```
brew install mkcert
````

or build from source (requires Go 1.10+)

```
go get -u github.com/FiloSottile/mkcert
$(go env GOPATH)/bin/mkcert
```

or use [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

For Arch Linux users, mkcert is available from AUR as [`mkcert`](https://aur.archlinux.org/packages/mkcert/) or [`mkcert-git`](https://aur.archlinux.org/packages/mkcert-git/).

```bash
git clone https://aur.archlinux.org/mkcert.git
cd mkcert
makepkg -si
```

### Windows

On Windows, use Chocolatey

```
choco install mkcert
```

or use Scoop

```
scoop bucket add extras
scoop install mkcert
```

or build from source (requires Go 1.10+), or use [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

If you're running into permission problems try running `mkcert` as an Administrator.

## Supported root stores

mkcert supports the following root stores:

* macOS system store
* Windows system store
* Linux variants that provide either
    * `update-ca-trust` (Fedora, RHEL, CentOS) or
    * `update-ca-certificates` (Ubuntu, Debian) or
    * `trust` (Arch)
* Firefox (macOS and Linux only)
* Chrome and Chromium
* Java (when `JAVA_HOME` is set)

To only install the local root CA into a subset of them, you can set the `TRUST_STORES` environment variable to a comma-separated list. Options are: "system", "java" and "nss" (includes Firefox).

## Advanced topics

### Advanced options

```
	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.
```

### Mobile devices

For the certificates to be trusted on mobile devices, you will have to install the root CA. It's the `rootCA.crt` file in the folder printed by `mkcert -CAROOT`.

On iOS, you can either use AirDrop, email the CA to yourself, or serve it from an HTTP server. After installing it, you must [enable full trust in it](https://support.apple.com/en-nz/HT204477). **Note**: earlier versions of mkcert ran into [an iOS bug](https://forums.developer.apple.com/thread/89568), if you can't see the root in "Certificate Trust Settings" you might have to update mkcert and [regenerate the root](https://github.com/FiloSottile/mkcert/issues/47#issuecomment-408724149).

For Android, you will have to install the CA and then enable user roots in the development build of your app. See [this StackOverflow answer](https://stackoverflow.com/a/22040887/749014).

### Using the root with Node.js

Node does not use the system root store, so it won't accept mkcert certificates automatically. Instead, you will have to set the [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) environment variable.

```
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.crt"
```

### Changing the location of the CA files

The CA certificate and its key are stored in an application data folder in the user home. You usually don't have to worry about it, as installation is automated, but the location is printed by `mkcert -CAROOT`.

If you want to manage separate CAs, you can use the environment variable `$CAROOT` to set the folder where mkcert will place and look for the local CA files.

### Installing the CA on other systems

Installing in the trust store does not require the CA key, so you can export the CA certificate and use mkcert to install it in other machines.

* Look for the `rootCA.crt` file in `mkcert -CAROOT`
* copy it to a different machine
* set `$CAROOT` to its directory
* run `mkcert -install`

Remember that mkcert is meant for development purposes, not production, so it should not be used on end users' machines, and that you should *not* export or share `rootCA.key`.
