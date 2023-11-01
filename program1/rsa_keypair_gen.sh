#!/bin/sh

dir=./clientkeys

if [ ! -d "$dir" ]
then
    mkdir $dir
fi

if [ ! -d "$dir/$1" ]
then
    mkdir $dir/$1
    touch $dir/$1/keypriv.pem
    openssl genrsa -out $dir/$1/keypriv.pem 2> /dev/null
    touch $dir/$1/keypub.pem
    openssl rsa -pubout -in $dir/$1/keypriv.pem -out $dir/$1/keypub.pem 2> /dev/null
fi