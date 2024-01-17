test -d /data || sudo mkdir /data
test -d /data && sudo chown -R dev:dev /data
/bin/bash -l -i