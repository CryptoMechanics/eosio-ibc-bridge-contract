RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
WHITE='\033[0;37m'
NC='\033[0m'

printf "\n"
printf "${BLUE}**********************************${NC}\n"
printf "${WHITE}Running Antelope IBC unit tests...${NC}\n"
printf "${BLUE}**********************************${NC}\n"
printf "\n"

printf "\n"
printf "${PURPLE}Test 1 : clear bridge contract${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat clear.sh)${NC}\n"
printf "\n"
./clear.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

# Using schedule version 36
printf "${PURPLE}Test 2 : init bridge contract${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat init-bridge-jungle4.sh)${NC}\n"
printf "\n"
./init-bridge-jungle4.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

# cleosj4 get block 24562480
printf "${PURPLE}Test 3 : prove block with new schedule ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-2.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-2.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

# cleosj4 get block 24562919
printf "${PURPLE}Test 4 : prove block ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-3.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-3.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"


# cleosj4 get block 24563672
printf "${PURPLE}Test 5 : prove new block with action${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-4.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-4.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"


# cleosj4 get block 25079023
printf "${PURPLE}Test 5 : prove new block with action, invalid state (ACTION_RETURN_VALUE activated on chain but not proven yet)${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-5.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-5.sh
printf "${RED} *** Should fail *** ${NC}\n"
printf "\n"

# cleosj4 get block 25078997
printf "${PURPLE}Test 6 : prove new block with action, activate ACTION_RETURN_VALUE feature ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-6.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-6.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"


# cleosj4 get block 25079023
printf "${PURPLE}Test 7 : prove new block with action, valid state${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-5.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-5.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

#cleosj4 get block 25105838
printf "${PURPLE}Test 8 : prove new block with action, invalid state (New pending schedule, but not proven yet) ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-8.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-8.sh
printf "${RED} *** Should fail *** ${NC}\n"
printf "\n"

#cleosj4 get block 25105815
printf "${PURPLE}Test 9 : prove new block with new schedule ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-7.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-7.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

#cleosj4 get block 25105838
printf "${PURPLE}Test 10 : prove new block with action, valid state ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-8.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-8.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

#cleosj4 get block 22531781
printf "${PURPLE}Test 11 : prove action with light proof scheme ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-light-jungle4-1.sh)${NC}\n"
printf "\n"
./prove-light-jungle4-1.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

exit 1

# cleosj4 get block 32312009
printf "${PURPLE}Test 3 : prove specific action ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-1.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-1.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

# cleosj4 get block 32313763
printf "${PURPLE}Test 4 : prove transfer action (2 authorities) ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-jungle4-2.sh)${NC}\n"
printf "\n"
./prove-heavy-jungle4-2.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

printf "${PURPLE}Test 6 : attempt to prove invalid heavy block (wrong chain) ${NC}\n"
printf "\n"
printf "Running command :\n"
printf "  ${ORANGE}$(cat prove-heavy-eos-1.sh)${NC}\n"
printf "\n"
./prove-heavy-eos-1.sh
printf "${RED} *** Should fail -> chain not supported *** ${NC}\n"
printf "\n"

exit 0

# cleosj4 get block 32331681
printf "${PURPLE}Test 4 : prove context-free action ${NC}\n"
printf "\n"

./prove-heavy-3.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

# cleosj4 get block 32310599
printf "${PURPLE}Test 5 : prove action using light proof ${NC}\n"
printf "\n"

./prove-light-1.sh
printf "${GREEN} *** Should succeed *** ${NC}\n"
printf "\n"

printf "${PURPLE}Test 6 : attempt to prove invalid heavy block (wrong chain) ${NC}\n"
printf "\n"

./prove-heavy-1.sh
printf "${RED} *** Should fail *** ${NC}\n"
printf "\n"

# Using schedule version 45
printf "${PURPLE}Test 7 : try to init chain with same name${NC}\n"
printf "\n"

./init-bridge-jungle4.sh
printf "${RED} *** Should fail *** ${NC}\n"
printf "\n"
