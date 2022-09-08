if [ $# -lt 1 ];
  then
    echo ERROR: parameters missing, must pass api as parameter
    exit 1;
  else
    scheduleStr=$(cleos -u $1 get schedule --json|jq '.active' -c)
    replacer="[\"block_signing_authority_v0\",{"

  #echo $scheduleStr
  #echo $replacer

  echo "${scheduleStr//[0,{/"$replacer"}"

fi
