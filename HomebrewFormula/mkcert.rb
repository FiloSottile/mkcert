class Mkcert < Formula
  desc "Simple tool to make locally-trusted development certificates"
  homepage "https://github.com/FiloSottile/mkcert"
  head "https://github.com/FiloSottile/mkcert.git"

  depends_on "go" => :build

  def install
    ENV["GOPATH"] = buildpath
    mkcertpath = buildpath/"src/github.com/FiloSottile/mkcert"
    mkcertpath.install buildpath.children
    cd mkcertpath do
      system "go", "build", "-o", bin/"mkcert"
      prefix.install_metafiles
    end
  end
end
  