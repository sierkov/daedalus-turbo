#! /bin/bash
export AGGREGATOR_ENDPOINT="https://aggregator.release-mainnet.api.mithril.network/aggregator"
export GENESIS_VERIFICATION_KEY="5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d"
for iter in `seq 1 5`; do
    test -d /data/mithril && rm -rf /data/mithril/*
    sh -c 'time /root/mithril/mithril-client-cli/mithril-client snapshot download --json --download-dir /data/mithril ccf885fbf0cb7908412588fe45dc109ef69c8fb47fb972be384bc9bf5a8ca64f' 2>&1 | tee mithril-$iter.log
done