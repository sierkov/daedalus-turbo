test -d /data && sudo chown -R dev:dev /data
test -d /data || mkdir /data
/bin/bash -l -i