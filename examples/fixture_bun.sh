#!/bin/sh
# TEST FIXTURE - synthetic runtime STUB for the node2shell-detector smoke runs; it is not a real node/bun and only prints canned output. Do not deploy.
case "$1" in
  --version|-v) echo "1.4.3";;
  *.js) echo '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_LENGTH_1","errno":-9,"name":"Error"}';;
  *) : ;;
esac
