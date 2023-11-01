#!/bin/sh

dir=./ttpkeys

if [ ! -d "$dir" ]
then
    mkdir $dir
fi

touch $dir/session_key.pem
