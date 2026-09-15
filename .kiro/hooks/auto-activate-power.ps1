# ecdsa-ocaml-engineering power activation hook
# Auto-activates when working in this project

if ($env:KIRO_POWER_AUTOACTIVATE -eq "true") {
    kiro powers activate -name ecdsa-ocaml-engineering
}
