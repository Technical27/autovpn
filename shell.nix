{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    libnl
    dbus
    pkg-config
  ];
}
