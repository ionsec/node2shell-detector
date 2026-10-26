#!/bin/sh
# TEST FIXTURE - synthetic runtime STUB for the node2shell-detector smoke runs; it is not a real node/bun and only prints canned output. Do not deploy.
case "$1" in
  --version|-v) echo "v24.22.0";;
  -p) echo '{"versions":{"node":"24.22.0","brotli":"1.2.0"},"shared":false}';;
  *.js) echo '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_LENGTH_1","errno":-9,"name":"Error"}';;
  *) : ;;
esac
