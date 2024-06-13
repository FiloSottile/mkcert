# mkcert

mkcert 是一个用于制作本地可信开发证书的简单工具。 它无需配置。

```
$ mkcert -install
在 "/Users/filippo/Library/Application Support/mkcert" 目录创建一个本地 CA 💥
本地 CA 现在安装在系统信任库中！ ⚡️
本地 CA 现在安装在 Firefox 信任库中（需要浏览器重启）！ 🦊

$ mkcert example.com "*.example.org" myapp.dev localhost 127.0.0.1 ::1
使用位于 "/Users/filippo/Library/Application Support/mkcert" 目录的本地 CA ✨

创建一个对以下名称有效的新证书 📜
 - "example.com"
 - "*.example.org"
 - "myapp.dev"
 - "localhost"
 - "127.0.0.1"
 - "::1"

证书位于 "./example.com+5.pem" and the key at "./example.com+5-key.pem" ✅
```

<p align="center"><img width="498" alt="Chrome and Firefox screenshot" src="https://user-images.githubusercontent.com/1225294/51066373-96d4aa80-15be-11e9-91e2-f4e44a3a4458.png"></p>

Using certificates from real certificate authorities (CAs) for development can be dangerous or impossible (for hosts like `localhost` or `127.0.0.1`), but self-signed certificates cause trust errors. Managing your own CA is the best solution, but usually involves arcane commands, specialized knowledge and manual steps.

mkcert automatically creates and installs a local CA in the system root store, and generates locally-trusted certificates. mkcert does not automatically configure servers to use the certificates, though, that's up to you.

## 安装

> **Warning**: the `rootCA-key.pem` file that mkcert automatically generates gives complete power to intercept secure requests from your machine. Do not share it.

### macOS

在 macOS 系统上, 使用 [Homebrew](https://brew.sh/)

```
brew install mkcert
brew install nss # if you use Firefox
```

或者 [MacPorts](https://www.macports.org/).

```
sudo port selfupdate
sudo port install mkcert
sudo port install nss # if you use Firefox
```

### Linux 

在 Linux 系统上, 首先安装 `certutil`.

```
sudo apt install libnss3-tools
    -or-
sudo yum install nss-tools
    -or-
sudo pacman -S nss
```

然后你就可以使用 [Linuxbrew](http://linuxbrew.sh/) 进行安装

```
brew install mkcert
````

或者从源码进行编译 (requires Go 1.10+)

```
go get -u github.com/FiloSottile/mkcert
$(go env GOPATH)/bin/mkcert
```

或者使用 [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

对于 Arch Linux 用户来说, mkcert 可以从 AUR  [`mkcert`](https://aur.archlinux.org/packages/mkcert/)  或者 [`mkcert-git`](https://aur.archlinux.org/packages/mkcert-git/) 获得.

```bash
git clone https://aur.archlinux.org/mkcert.git
cd mkcert
makepkg -si
```

### Windows

在 Windows 系统上, 使用 Chocolatey

```
choco install mkcert
```

或使用 Scoop

```
scoop bucket add extras
scoop install mkcert
```

或从源码 (requires Go 1.10+) 编译, 或使用 [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases).

如果您遇到权限问题，请尝试以管理员身份运行 `mkcert` 。

## 支持的根存储

mkcert 支持以下根存储：

* macOS 系统存储
* Windows 系统存储
* Linux 版本，能够提供
    * `update-ca-trust` (Fedora, RHEL, CentOS) 或
    * `update-ca-certificates` (Ubuntu, Debian) 或
    * `trust` (Arch)
* Firefox ( 仅支持 macOS and Linux )
* Chrome 和 Chromium
* Java (当 `JAVA_HOME` 已经设置)

如果仅仅将本地根 CA 安装到它们的子集中， 您可以将 `TRUST_STORES` 环境变量设置为以逗号分隔的列表。 选项包括：“system” ，“java” 和 “nss”（包括 Firefox ）。

## 高级主题

### 高级选项

```
	-cert-file FILE, -key-file FILE, -p12-file FILE
	    自定义输出路径。

	-client
	    生成用于客户端身份校验的证书。

	-ecdsa
	    使用ECDSA密钥生成证书。

	-pkcs12
	    生成 “.p12”PKCS＃12 文件，也称为“.pfx”文件，
	    包含传统应用程序证书和密钥。

	-csr CSR
	   根据提供的 CSR 生成证书。 与除 -install 和 -cert-file 之外的所有其他标志和参数冲突。
```

### 移动设备

要使移动设备上的证书受信任，您必须安装根 CA 。 它是 `mkcert -CAROOT` 打印的文件夹中的 `rootCA.pem` 文件。

在 iOS 上，您可以使用 AirDrop ，通过电子邮件将 CA 发送给自己，也可以从 HTTP 服务器提供。 安装后，你必须 [对其开启完全信任](https://support.apple.com/en-nz/HT204477). **注意**: 早期版本的 mkcert 遇到[一个 iOS 漏洞](https://forums.developer.apple.com/thread/89568), 如果您无法在“证书信任设置”中看到 root ，则可能需要更新 mkcert 并[重新生成 root](https://github.com/FiloSottile/mkcert/issues/47#issuecomment-408724149).

对于 Android ，您必须安装 CA ，然后在应用程序的开发版本中启用用户 roots。 见 [this StackOverflow answer](https://stackoverflow.com/a/22040887/749014).

### 将  root 与 Node.js 一起使用

Node不使用系统根存储，因此它不会自动接受 mkcert 证书。 相反，你必须设置 [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) 环境变量.

```
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

### 更改 CA 文件的位置

CA 证书及其密钥存储在用户主目录的应用程序数据文件夹中。 您通常不必担心它，因为安装是自动化的，但位置由 `mkcert -CAROOT` 打印。

如果要管理单独的 CA ，可以使用环境变量 `$ CAROOT` 来设置 mkcert 将放置的文件夹，并查找本地 CA 文件。

### 在其他系统上安装 CA 。

在信任库中安装不需要 CA 密钥，因此您可以导出 CA 证书并使用 mkcert 将其安装在其他计算机上。

* 查找位于 `mkcert -CAROOT` 中的 `rootCA.pem` 文件
* 将其复制到另一台机器
* 直接给它设置 `$CAROOT` 
* 运行 `mkcert -install`

请记住，mkcert 仅用于开发环境，而不是生产环境，因此不应在终端用户的计算机上使用，并且您*不*应该导出或共享 `rootCA-key.pem` 文件。
