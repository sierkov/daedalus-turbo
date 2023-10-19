for dir in /data/www /data/indices; do
    test -d $dir  && sudo chown -R dev:dev $dir
done
/bin/bash -l -i