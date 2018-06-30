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

Using certificates from real CAs for development can be dangerous or impossible (for hosts like `localhost` or `127.0.0.1`), but self-signed certificates cause trust errors. Managing your own CA is the best solution, but usually involves arcane commands, specialized knowledge and manual steps.

mkcert automatically creates and installs a local CA in the system root store, and generates locally-trusted certificates.

## Installation

On macOS, use Homebrew.

```
brew install --HEAD https://github.com/FiloSottile/mkcert/raw/master/HomebrewFormula/mkcert.rb
brew install nss # if you use Firefox
```

On Linux (`-install` support coming soon!), use [the pre-built binaries (again, coming soon)](https://github.com/FiloSottile/mkcert/releases), or build from source (requires Go 1.10+).

```
$ git clone https://github.com/FiloSottile/mkcert
$ cd mkcert && make
```

On ArchLinux use your [AUR helper](https://wiki.archlinux.org/index.php/AUR_helpers) to install mkcert from the [PKGBUILD](https://aur.archlinux.org/packages/mkcert-git/):
```
yaourt -S mkcert-git
```

Windows will be supported next.

## Advanced topics

### Changing the location of the CA files

The CA certificate and its key are stored in an application data folder in the user home. You usually don't have to worry about it, as installation is automated, but if you need it it's printed in the first line of the mkcert output.

If you want to manage separate CAs, you can use the environment variable `CAROOT` to set the folder where mkcert will place and look for the local CA files.

### Installing the CA on other computers

Installing in the trust store does not require the CA key, so you can export just the CA certificate and use mkcert to install it in other machines. For example, you can decide to commit just `rootCA.pem` and not its key to version control.

* Look for the `rootCA.pem` file in `CAROOT` or in the default folder (see above)
* copy it to a different machine
* set `CAROOT` to its directory
* run `mkcert -install`

Remember that mkcert is meant for development purposes, not production, so it should not be used on end users' machines.

---

This is not an official Google project, just some code that happens to be owned by Google.
