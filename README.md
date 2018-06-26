# mkcert

mkcert is a simple tool for making locally-trusted development certificates. There is no configuration.

```
$ mkcert -install
Created a new local CA at "/Users/filippo/Library/Application Support/mkcert" 💥
The local CA is now installed in the system trust store! ⚡️

$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
Using the local CA at "/Users/filippo/Library/Application Support/mkcert" ✨

Created a new certificate valid for the following names 📜
 - "example.com"
 - "myapp.dev"
 - "localhost"
 - "127.0.0.1"
 - "::1"

The certificate is at "./example.com+4.pem" and the key at "./example.com+4-key.pem" ✅
```

<p align="center"><img width="444" alt="Chrome screenshot" src="https://user-images.githubusercontent.com/1225294/41887838-7acd55ca-78d0-11e8-8a81-139a54faaf87.png"></p>

Using certificates from real CAs for development can be dangerous or impossible (for hosts like `localhost` or `127.0.0.1`), but self-signed certificates cause trust errors. Managing your own CA is the best solution, but usually involves arcane commands, specialized knowledge and manual steps.

mkcert automatically creates and installs a local CA in the system root store, and generates locally-trusted certificates.

## Installation

On macOS, use Homebrew.

```
brew install --HEAD FiloSottile/mkcert/mkcert
```

On Linux, use [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases), or build from source.

```
$ git clone https://github.com/FiloSottile/mkcert
$ cd mkcert && make
```

Windows will be supported soon.

## Changing the location of the CA files

TODO

## Installing the CA on other computers

TODO

Remember that mkcert is meant for development purposes, not production, so it should not be used on users' machines.

---

This is not an official Google project, just some code that happens to be owned by Google.
