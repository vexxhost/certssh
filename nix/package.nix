{
  lib,
  buildGoModule,
  openssh,
  src,
  version,
}:

buildGoModule {
  pname = "certssh";
  inherit version src;

  vendorHash = "sha256-lQIA3VDPF1oSClhxerUjn8fwYPQAfWisBcpjuoz3Eao=";

  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];

  # The agent tests drive the real OpenSSH client against in-process servers.
  nativeCheckInputs = [ openssh ];

  postInstall = ''
    find $out/bin -type f ! -name certssh -delete
  '';

  meta = {
    description = "SSH agent that signs certificates from OpenBao or Vault on demand, picking the right one for each host";
    homepage = "https://github.com/vexxhost/certssh";
    license = lib.licenses.asl20;
    mainProgram = "certssh";
    platforms = lib.platforms.unix;
  };
}
