#!/bin/bash
dir=/home/backup/db/logs/`date '+%Y%m%d%H%M%S'`
mkdir $dir
rsync -a mysql@db:/var/log/mysql/ $dir
