with import <nixpkgs> {};
stdenv.mkDerivation {
  name = "kalix-env";
  buildInputs = [ pkgconfig openssl dbus rustup gnuplot valgrind linuxPackages.perf ];
}
