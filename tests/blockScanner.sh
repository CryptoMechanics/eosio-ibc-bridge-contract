#!/bin/bash

if [ $# -eq 0 ]
then
  echo "Must supply start and count params"
  exit 1
fi

start=${1}
count=${2}
total=$(( $1 + $2 ))

echo "$start"
echo "$count"
echo "$total"

for i in $(seq $start $total)
do
   echo "Get block $i..."
  # echo "$((a + 1))"
   cleos -u https://eostestnet.goldenplatform.com get block $i |jq '.transactions'
done
