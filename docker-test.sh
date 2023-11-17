test -d /data || sudo mkdir /data
test -d /data && sudo chown -R dev:dev /data
export DT_LOG=/home/dev/dt/log/dt.log
/bin/bash -l -i