#! /bin/sh
if [ -z "$1" ]; then
    echo "Usage: track-dns.sh <output-file>"
    exit 1
fi
OUT_FILE=$1
test -f $OUT_FILE && rm $OUT_FILE
while [ true ]; do
    echo "DNS TRACKING CYCLE" >> $OUT_FILE
    echo "==================" >> $OUT_FILE
    date >> $OUT_FILE
    echo "" >> $OUT_FILE
    dig relays-new.cardano-mainnet.iohk.io >> $OUT_FILE
    sleep 1800
done
