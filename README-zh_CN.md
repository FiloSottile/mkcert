# mkcert

[English](README.md)

mkcert 是用于创建本地信任证书的简单工具。它是免配的。

```
$ mkcert -install
Created a new local CA 💥
The local CA is now installed in the system trust store! ⚡️
The local CA is now installed in the Firefox trust store (requires browser restart)! 🦊

$ mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1

Created a new certificate valid for the following names 📜
 - "example.com"
 - "*.example.com"
 - "example.test"
 - "localhost"
 - "127.0.0.1"
 - "::1"

The certificate is at "./example.com+5.pem" and the key at "./example.com+5-key.pem" ✅
```

<p align="center"><img width="498" alt="Chrome and Firefox screenshot" src="https://user-images.githubusercontent.com/1225294/51066373-96d4aa80-15be-11e9-91e2-f4e44a3a4458.png"></p>

在开发环境中使用正式证书机构颁发的证书是有危险或不可能的（例如类似于 `example.test`, `localhost` 或 `127.0.0.1` 的主机），但自签名证书会引起信任错误。管理自己的 CA 是最好的解决方案，但通常需要神秘的命令，特定的知识和手动步骤。

mkcert 自动在系统根存储中创建和安装一个本地 CA，同时生成本地信任证书。不过 mkcert 不会自动配置服务器来使用证书，这取决于你。

## 安装

> **警告**: mkcert 自动生成的 `rootCA-key.pem` 文件提供了拦截你机器安全请求的完全能力。不要分享。

### macOS

macOS 上, 使用 [Homebrew](https://brew.sh/)

```
brew install mkcert
brew install nss # if you use Firefox
```

或 [MacPorts](https://www.macports.org/).

```
sudo port selfupdate
sudo port install mkcert
sudo port install nss # if you use Firefox
```

### Linux

Linux 上, 首先安装 `certutil`.

```
sudo apt install libnss3-tools
    -or-
sudo yum install nss-tools
    -or-
sudo pacman -S nss
    -or-
sudo zypper install mozilla-nss-tools
```

然后可以使用 [Homebrew on Linux](https://docs.brew.sh/Homebrew-on-Linux) 来安装

```
brew install mkcert
```

或从源码构建（依赖 Go 1.13+）

```
git clone https://github.com/FiloSottile/mkcert && cd mkcert
go build -ldflags "-X main.Version=$(git describe --tags)"
```

或使用 [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases) 。

对于 Arch Linux 用户， [`mkcert`](https://www.archlinux.org/packages/community/x86_64/mkcert/) 在 Arch Linux 的官方仓库可用。

```
sudo pacman -Syu mkcert
```

### Windows

Windows 上, 使用 [Chocolatey](https://chocolatey.org)

```
choco install mkcert
```

或使用 Scoop

```
scoop bucket add extras
scoop install mkcert
```

或从源码构建（依赖 Go 1.10+)，或使用 [the pre-built binaries](https://github.com/FiloSottile/mkcert/releases)。

若运行 `mkcert` 出现权限问题，试着用管理员来运行。

## 支持的根存储

mkcert 支持以下根存储：

* MacOS 系统存储
* Windows 系统存储
* 同样提供如下 Linux 变体
    * `update-ca-trust` (Fedora, RHEL, CentOS) 或
    * `update-ca-certificates` (Ubuntu, Debian, OpenSUSE, SLES) 或
    * `trust` (Arch)
* Firefox (仅 macOS 和 Linux)
* Chrome 和 Chromium
* Java (当 `JAVA_HOME` 设置)

要安装本地 CA 到它们的子集中，你可以将环境变量 `TRUST_STORES` 设置为逗号分隔的列表。选项为："system", "java" 和 "nss" (包含 Firefox)。

## 高级主题

### 高级选项

```
	-cert-file FILE, -key-file FILE, -p12-file FILE
	    定制输出路径。

	-client
		生成用于特定客户端认证的证书		

	-ecdsa
		使用 ECDSA 密钥生成证书。

	-pkcs12
		生成 ".p12" PKCS #12 文件，也称为 ".pfx" 文件，
		包含应用于旧版应用的证书和密钥。

	-csr CSR
		基于提供的 CSR 生成证书。与其他所有标志相冲突，同时接受 -install 和 -cert-file 参数。
```

> **注意：** 你_必须_将这些选项放在域名列表前面。

#### 示例

```
mkcert -key-file key.pem -cert-file cert.pem example.com *.example.com
```

### S/MIME

mkcert 在提供 email 地址时会自动生成 S/MIME 证书。

```
mkcert filippo@example.com
```

### 移动设备

要在移动设备上信任证书，必须安装 root CA。它是位于 `mkcert -CAROOT` 命令所输出目录中的 `rootCA.pem` 文件。

iOS 上，也可以使用 AirDrop，通过 Email 将 CA 发送给自己，或从 HTTP 服务来得到。打开之后，你需要 [在 Settings > Profile Downloaded 中安装它](https://github.com/FiloSottile/mkcert/issues/233#issuecomment-690110809) 然后 [启用对其完全信任](https://support.apple.com/en-nz/HT204477)。

对于 Android，你必须安装该 CA 然后在 app 的开发构建中启用 user root。参考 [this StackOverflow answer](https://stackoverflow.com/a/22040887/749014)。

### 在 Node.js 中使用

Node 未使用系统根存储，所以它不能使用 mkcert 来自动处理。代替方案是，你必须去设置 [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) 环境变量。

```
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

### 修改 CA 文件位置

CA 证书和其密钥存储于用户 home 中的应用程序数据目录。通常不需要关系它，因为安装时会自动处理，通过命令 `mkcert -CAROOT` 可以输出该位置。

若你想要管理这些分散的 CAs，可以使用环境变量 `$CAROOT` 设置设置一个目录来存储和查找这些本地的 CA 文件。

### 在其他系统安装 CA

在信任的存储系统中安装时 CA 密钥不是必须的，因此你可以导出 CA 证书同时使用 mkcert 在其他机器上安装它。

* 在  `mkcert -CAROOT` 中查找 `rootCA.pem` 文件
* 拷贝到其他机器
* 设置 `$CAROOT` 为其存储目录
* 运行 `mkcert -install`

记住 mkcert 用于开发目的，而不是生产，因此它不应该被用在用户机器终端上，同时你*不要*导出或分享 `rootCA-key.pem`。
