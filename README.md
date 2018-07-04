# mkcert

mkcert is a simple tool for making locally-trusted development certificates. It requires no configuration.

```
$ mkcert -install
Created a new local CA at "/Users/filippo/Library/Application Support/mkcert" 💥
The local CA is now installed in the system trust store! ⚡️
The local CA is now installed in the Firefox trust store (requires restart)! 🦊

$ mkcert example.com '*.example.org' myapp.dev localhost 127.0.0.1 ::1
Using the local CA at "/Users/filippo/Library/Application Support/mkcert" ✨

Created a new certificate valid for the following names 📜
 - "example.com"
 - "*.example.org"
 - "myapp.dev"
 - "localhost"
 - "127.0.0.1"
 - "::1"

The certificate is at "./example.com+5.pem" and the key at "./example.com+5-key.pem" ✅
```

<p align="center"><img width="444" alt="Chrome screenshot" src="https://user-images.githubusercontent.com/1225294/41887838-7acd55ca-78d0-11e8-8a81-139a54faaf87.png"></p>

Using certificates from real certificate authorities (CAs) for development can be dangerous or impossible (for hosts like `localhost` or `127.0.0.1`), but self-signed certificates cause trust errors. Managing your own CA is the best solution, but usually involves arcane commands, specialized knowledge and manual steps.

mkcert automatically creates and installs a local CA in the system root store, and generates locally-trusted certificates.

## Installation

On macOS, use Homebrew.

```
brew install mkcert
brew install nss # if you use Firefox
```

On Linux, install `certutil`

```
sudo apt install libnss3-tools
    -or-
sudo yum install nss-tools
```

and build from source (requires Go 1.10+), or use [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

```
go get -u github.com/FiloSottile/mkcert
$(go env GOPATH)/bin/mkcert
```

Windows will be supported next. (PRs welcome!)

> **Warning**: the `rootCA-key.pem` file that mkcert automatically generates gives complete power to intercept secure requests from your machine. Do not share it.

## Advanced topics

### Mobile devices

For the certificates to be trusted on mobile devices, you will have to install the root CA. It's the `rootCA.pem` file in the folder printed by `mkcert -CAROOT`.

On iOS, you can either email the CA to yourself, or serve it from an HTTP server. After installing it, you must [enable full trust in it](https://support.apple.com/en-nz/HT204477).

For Android, you will have to install the CA and then enable user roots in the development build of your app. See [this StackOverflow answer](https://stackoverflow.com/a/22040887/749014).

### Changing the location of the CA files

The CA certificate and its key are stored in an application data folder in the user home. You usually don't have to worry about it, as installation is automated, but the location is printed by `mkcert -CAROOT`.

If you want to manage separate CAs, you can use the environment variable `$CAROOT` to set the folder where mkcert will place and look for the local CA files.

### Installing the CA on other systems

Installing in the trust store does not require the CA key, so you can export the CA certificate and use mkcert to install it in other machines.

* Look for the `rootCA.pem` file in `mkcert -CAROOT`
* copy it to a different machine
* set `$CAROOT` to its directory
* run `mkcert -install`

Remember that mkcert is meant for development purposes, not production, so it should not be used on end users' machines, and that you should *not* export or share `rootCA-key.pem`.

---

This is not an official Google project, just some code that happens to be owned by Google.
