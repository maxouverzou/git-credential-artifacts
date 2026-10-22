# Test-only baseline Git. Pin its source separately from the current nixpkgs Git;
# disable unrelated HTTP/GUI/perl features but retain real credential/cache code.
{
  stdenv,
  fetchurl,
  lib,
  zlib,
  libiconv,
  perl,
  bash,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "git-artifacts-integration-baseline";
  version = "2.45.0";
  src = fetchurl {
    url = "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${finalAttrs.version}.tar.xz";
    hash = "sha256-CqwgC9BkduffH/Am6xI8aCe8EP5p0oI7S/Lr6+WVNCk=";
  };
  nativeBuildInputs = [ perl ];
  buildInputs = [ zlib ] ++ lib.optional stdenv.hostPlatform.isDarwin libiconv;
  dontConfigure = true;
  enableParallelBuilding = true;
  # GCC 16 defaults to C23, whose unreachable macro conflicts with Git 2.45.
  # Use its original GNU C dialect, without changing credential/cache code.
  env.NIX_CFLAGS_COMPILE = "-std=gnu11";
  makeFlags = [
    "prefix=$(out)"
    "SHELL_PATH=${bash}/bin/bash"
    "NO_CURL=1"
    "NO_OPENSSL=1"
    "NO_GETTEXT=1"
    "NO_PERL=1"
    "NO_PYTHON=1"
    "NO_TCLTK=1"
  ];
  # Project integration checks exercise the needed commands; this is not a claim
  # that the full upstream Git suite or its disabled transports were certified.
  doCheck = false;
  meta.platforms = lib.platforms.unix;
})
