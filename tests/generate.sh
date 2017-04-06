#!/bin/bash

host='testhost'

message="$host systemd[1]: Looping too fast. Throttling execution a little."

for i in {1..10} ; do
	echo $i
	echo "$message" | netcat -u -w0 192.168.56.10 514
done
