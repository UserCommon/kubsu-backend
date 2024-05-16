let
  pkgs = import <nixpkgs> {};
in pkgs.mkShell {
  shellHook = ''
    export user=my_user
    export password=123
    export host=0.0.0.0
    export port=3306
    export database=my_db
  '';
  packages = [
    (pkgs.python3.withPackages (python-pkgs: [
      python-pkgs.jinja2
      python-pkgs.mysql-connector
      python-pkgs.bcrypt
    ]))
  ];
}
