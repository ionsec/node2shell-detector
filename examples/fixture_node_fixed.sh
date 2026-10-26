#!/bin/sh
# TEST FIXTURE - synthetic runtime STUB for the node2shell-detector smoke runs; it is not a real node/bun and only prints canned output. Do not deploy.
case "$1" in
  --version|-v) echo "v24.22.1";;
  -p) echo '{"versions":{"node":"24.22.1","brotli":"1.2.0"},"shared":false}';;
  *.js) echo '{"ok":false,"code":"ERR__ERROR_FORMAT_BLOCK_SWITCH","errno":-17,"name":"Error"}';;
  *) : ;;
esac
