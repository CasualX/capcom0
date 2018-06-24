@ECHO OFF
REM Build elevate with the right manifest to requestAdministrator when run.
SHIFT
SET LINK_ARGS=-C link-arg=^"/MANIFEST:embed^" -C link-arg=^"/MANIFESTUAC:level=\^"requireAdministrator\^" uiAccess=\^"false\^"^"
ECHO Building elevate...
cargo rustc --bin elevate %* -- %LINK_ARGS%
ECHO Building recover...
cargo rustc --bin recover %* -- %LINK_ARGS%
