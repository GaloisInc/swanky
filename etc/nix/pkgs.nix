{}:
let sources = import ../nix/sources.nix;
in
(import sources.nixpkgs)
{
  overlays = [ (import sources.rust-overlay) ];
}
