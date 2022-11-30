#!/bin/bash
dir=/home/backup/web/logs/`date '+%Y%m%d%H%M%S'`
mkdir $dir
rsync -a web@web:/home/web/web-server/web-server.log $dir