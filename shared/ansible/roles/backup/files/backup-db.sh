#!/bin/bash
dir=/home/backup/db/`date '+%Y%m%d%H%M%S'`
mkdir $dir
mkdir $dir/logs
rsync -a mysql@db:/var/log/mysql/ $dir/logs

mysqldump -h db --databases imovies > $dir/mysqldump.sql