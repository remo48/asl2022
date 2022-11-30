#!/bin/bash
dir=/home/backup/ca/certs/`date '+%Y%m%d%H%M%S'`
mkdir $dir
rsync -a ca@ca:/home/ca/ca/certs/ $dir