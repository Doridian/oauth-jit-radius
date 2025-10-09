{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: 
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        package = pkgs.buildGoModule {
          pname = "oauth-jit-radius";
          version = "1.0.0";
          src = ./.;
          vendorHash = "sha256-S0LHAzQ6MjZrTWDDlazuekcyjATaPmZCwgNOpKOAeTc=";
          buildInputs = [];
        };
      in
      {
        packages = {
          default = package;
          oauth-jit-radius = package;
        };
      });
}
