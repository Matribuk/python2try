#!/bin/bash

rm -rf -f ./database/data/
mkdir ./database/data/
docker-compose up --build