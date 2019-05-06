@ECHO OFF
REM Build elevate with the right manifest to requestAdministrator when run.
SHIFT
SET LINK_ARGS=-C link-arg=^"/MANIFEST:embed^" -C link-arg=^"/MANIFESTUAC:level=\^"requireAdministrator\^" uiAccess=\^"false\^"^"
ECHO Building recover...
cargo rustc --bin recover %* -- %LINK_ARGS%
ECHO Building elevate...
cargo rustc --example elevate %* -- %LINK_ARGS%
ECHO Building bypass...
cargo rustc --example bypass %* -- %LINK_ARGS%
