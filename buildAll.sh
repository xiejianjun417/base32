#!/bin/bash
CUR_PATH=`pwd`

#clean all projects
make -C "${CUR_PATH}/src" clean

make -C "${CUR_PATH}/src" all

