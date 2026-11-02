echo "Using Node.js $(node --version)"

node -e 'process.exit(parseInt(process.versions.node, 10))' &> /dev/null
NODE_VERSION=$?
export NODE_OPTIONS='--import=ts-blank-space/register --tls-cipher-list="ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384"'

if [ "$NODE_VERSION" -eq 20 ]; then
  export NODE_OPTIONS="$NODE_OPTIONS --require=\"$(pwd)/tools/node20.cjs\""
fi
