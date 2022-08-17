#include <bridge.hpp>


//edge cases to test :
//
// EOS Mainnet -
//
//  739450 new_producers announced (v1 to v2)
//  739450 schedule_version incremented
//  793422 new_producers announced (v2 to v3)
//  793758 schedule_version incremented
//  261374141 new_producer_schedule
//  261374478 schedule_version incremented
//
// Kylin -
//
//  197997700 new_producer_schedule announced
//  197998035 schedule version incremented
//
// UX Network Mainnet -
//
//  5867172 new_producer_schedule announced (v1 to v2)
//  5867174 schedule_version incremented
//
// EOS Testnet
//
//  41012565 two block producer signatures
//  41012657 new_producer_schedule announced (v17 to v18)
//  41012994 schedule_version incremented
//  41018201 new_producer_schedule announced (v18 to v19)
//  41018538 schedule_version incremented
//  41195321 new_producer_schedule announced (v20 to v21)
//  41195657 schedule_version incremented
//
// UX Testnet
//
//  128575774 new_producer_schedule announced (v15 to v16)
//  128576110 schedule_version incremented
//
//


//Set 1st bit to 0 a node is a left side node for merkle concatenation + hash
checksum256 make_canonical_left(const checksum256& val) {
   std::array<uint8_t, 32> arr = val.extract_as_byte_array();
   arr[0] &= 0x7F;
   checksum256 canonical_l = checksum256(arr);
   return canonical_l;
}

//Set 1st bit to 1 a node is a right side node for merkle concatenation + hash
checksum256 make_canonical_right(const checksum256& val) {
   std::array<uint8_t, 32> arr = val.extract_as_byte_array();
   arr[0] |= 0x80;
   checksum256 canonical_r = checksum256(arr);
   return canonical_r;
}

//Creates a canonically correct pair of nodes, with proper 1st bit masking
auto make_canonical_pair(const checksum256& l, const checksum256& r) {
  return std::make_pair(make_canonical_left(l), make_canonical_right(r));
};

//Compute the next power of 2 for a given number
constexpr uint64_t next_power_of_2(uint64_t value) {
   value -= 1;
   value |= value >> 1;
   value |= value >> 2;
   value |= value >> 4;
   value |= value >> 8;
   value |= value >> 16;
   value |= value >> 32;
   value += 1;   return value;
}

//Compute the number of layers required to create a merkle tree for a given number of leaves
constexpr int clz_power_2(uint64_t value) {

   int lz = 64;

   if (value) lz--;
   if (value & 0x00000000FFFFFFFFULL) lz -= 32;
   if (value & 0x0000FFFF0000FFFFULL) lz -= 16;
   if (value & 0x00FF00FF00FF00FFULL) lz -= 8;
   if (value & 0x0F0F0F0F0F0F0F0FULL) lz -= 4;
   if (value & 0x3333333333333333ULL) lz -= 2;
   if (value & 0x5555555555555555ULL) lz -= 1;

   return lz;
}

//Compute the maximum number of layers of a merkle tree for a given number of leaves
constexpr int calculate_max_depth(uint64_t node_count) {
   if (node_count == 0) {
      return 0;
   }
   auto implied_count = next_power_of_2(node_count);
   return clz_power_2(implied_count) + 1;
}

//Moves nodes from one container to another
template<typename ContainerA, typename ContainerB>
inline void move_nodes(ContainerA& to, const ContainerB& from) {
   to.clear();
   to.insert(to.begin(), from.begin(), from.end());
}

//Moves nodes from one container to another
template<typename Container>
inline void move_nodes(Container& to, Container&& from) {
   to = std::forward<Container>(from);
}

//Concatenate and hash a pair of values and return the resulting digest
checksum256 hashPair( std::pair<checksum256, checksum256> p){

  std::array<uint8_t, 32> arr1 = p.first.extract_as_byte_array();
  std::array<uint8_t, 32> arr2 = p.second.extract_as_byte_array();

  std::array<uint8_t, 64> result;
  std::copy (arr1.cbegin(), arr1.cend(), result.begin());
  std::copy (arr2.cbegin(), arr2.cend(), result.begin() + 32);

  void* ptr = static_cast<void*>(result.data());

  return sha256((char*)ptr, 64);

}

//Append a new leaf to an incremental merkle tree data structure, returning the resulting merkle root
const checksum256& append(const checksum256& digest, std::vector<checksum256> &_active_nodes, uint64_t node_count) {
  bool partial = false;
  uint32_t max_depth = calculate_max_depth(node_count + 1);

  auto implied_count = next_power_of_2(node_count);

  auto current_depth = max_depth - 1;
  auto index = node_count;
  auto top = digest;
  auto active_iter = _active_nodes.begin();
  std::vector<checksum256> updated_active_nodes;
  updated_active_nodes.reserve(max_depth);

  while (current_depth > 0) {
     if (!(index & 0x1)) {

        if (!partial) {
           updated_active_nodes.emplace_back(top);
        }

        top = hashPair(make_canonical_pair(top, top));

        partial = true;
     } else {

        const auto& left_value = *active_iter;
        ++active_iter;

        if (partial) {
           updated_active_nodes.emplace_back(left_value);
        }

        top = hashPair(make_canonical_pair(left_value, top));

     }

     current_depth--;
     index = index >> 1;
  }

  updated_active_nodes.emplace_back(top);

  move_nodes(_active_nodes, std::move(updated_active_nodes));

  node_count++;

  return _active_nodes.back();

}

//Given a proof and a specific leaf, verify its inclusion in a merkle tree with the given root
bool proof_of_inclusion(std::vector<checksum256> proof_nodes, checksum256 target, checksum256 root ) {

  //print("proof_nodes[0] : ", proof_nodes[0], "\n");
  //print("target : ", target, "\n");
  //print("root : ", root, "\n");

   checksum256 hash = target;

   auto p_itr = proof_nodes.begin();

   while (p_itr != proof_nodes.end()){

      checksum256 &node = *p_itr;
      
      std::array<uint8_t, 32> arr = node.extract_as_byte_array();

      bool isLeft = arr[0]<128;

      if (!isLeft) {
         node = make_canonical_right(node);
         hash = make_canonical_left(hash);

  //print("can r node : ", node, "\n");
  //print("can l hash : ", hash, "\n");

         hash = hashPair(std::make_pair(hash, node));
  //print("res hash : ", hash, "\n");
      }
      else {
         hash = make_canonical_right(hash);
         node = make_canonical_left(node);

  //print("can l node : ", node, "\n");
  //print("can r hash : ", hash, "\n");

         hash = hashPair(std::make_pair(node, hash));
  //print("res hash : ", hash, "\n");
      }

      p_itr++;
   }

  return hash == root;

}

//Find the producer's authority from the schedule
block_signing_authority_v0 get_producer_authority(bridge::schedule schedule, name producer){
  for (int i = 0; i <schedule.producers.size(); i++){
    if (schedule.producers[i].producer_name == producer){
      return std::get<0>(schedule.producers[i].authority);
    }
  }
  check(false, "producer not in current schedule");
}


//Verify if a vector contains a given element
template <typename T>
bool contains(std::vector<T> vec, const T & elem)
{
  return any_of(vec.begin(), vec.end(), [&](const auto & x){
    return x == elem;
  });
}

//Verify if the authorization of a given block producer has been satisfied (compatible with weight msig)
bool auth_satisfied(const block_signing_authority_v0 authority, std::vector<public_key> signing_keys) {
  uint32_t weight = 0;
  for (const auto& kpw : authority.keys){
     if (contains(signing_keys, kpw.key)) {
         weight += kpw.weight;
        if (weight >= authority.threshold)
           return true;
     }
  }
  print("insufficient WTMsig weight : ", weight, " (threshold : ", authority.threshold, ")\n");
  return false;
}

//prepare the digest to sign from its base components, recover the key(s) from the signature(s) and verify if we enough signatures matching keys to satisfy authorization requirements
 void check_signatures(name producer, std::vector<signature> producer_signatures, checksum256 header_digest, checksum256 previous_bmroot, bridge::schedule producer_schedule, checksum256 producer_schedule_hash ){

  checksum256 header_bmroot = hashPair( std::make_pair( header_digest, previous_bmroot) );
  checksum256 digest_to_sign = hashPair( std::make_pair( header_bmroot, producer_schedule_hash) );

  block_signing_authority_v0 auth = get_producer_authority(producer_schedule, producer);
  std::vector<public_key> signing_keys;
  for (const auto& sig : producer_signatures) {
    signing_keys.push_back(recover_key(digest_to_sign, sig));
  }

  check(auth_satisfied(auth, signing_keys), "invalid BFT block signatures");

}

//verify the integrity and authentiticy of a block header, compute and return its merkle root
checksum256 check_block_header(bridge::sblockheader block, std::vector<checksum256> &active_nodes, uint64_t node_count, bridge::schedule& producer_schedule, checksum256& producer_schedule_hash){

  //schedule version of the header must match either current or pending schedule version
  check(block.header.schedule_version == producer_schedule.version || block.header.schedule_version == producer_schedule.version -1, "invalid schedule version");

  checksum256 header_digest = block.header.digest();

  checksum256 previous_bmroot = append(block.header.previous, active_nodes, node_count); //we must calculate previous_bmroot ourselves, otherwise we can't trust the activeNodes
  checksum256 current_bmroot = append(block.header.block_id(), active_nodes, node_count); //we can now safely calculate the current_bmroot, which we will store

  // if block contains a new schedule, we use that schedule hash from now on when preparing the digest to sign to verify signatures
  if (block.header.header_extensions.size() > 0) {
    for (const auto& ext : block.header.header_extensions) {
      if (ext.first == 1) {
        auto new_producer_schedule_hash_packed = ext.second;
        producer_schedule_hash = sha256(new_producer_schedule_hash_packed.data(), new_producer_schedule_hash_packed.size());

      }
    }
  }

  //check signatures
  check_signatures(block.header.producer, block.producer_signatures, header_digest, previous_bmroot, producer_schedule, producer_schedule_hash);

  return previous_bmroot;

}

//attempt to perform garbage collection for <count> proofs. If <count> is 0, attempt to perform garbage collection for all
void bridge::gc_proofs(name chain, int count){
  
  time_point cts = current_time_point();

  proofstable _proofstable(_self, chain.value);

  int distance = std::distance(_proofstable.begin(), _proofstable.end());

  auto block_height_index = _proofstable.get_index<"height"_n>();
  auto expiry_index = _proofstable.get_index<"expiry"_n>();

  auto h_itr = block_height_index.rbegin();

  if (count == 0 ) count = distance;

  int counter = 0;
  int gc_counter = 0;

  do {

    auto e_itr = expiry_index.begin();

    //We always keep the successful proof of the highest blockchain height
    if (e_itr->block_height < h_itr->block_height && cts > e_itr->expiry){ 
      expiry_index.erase(e_itr);
      gc_counter++;
    } else break;
 
    counter++;
  } while (counter<count) ;

  if (gc_counter>0) print("collected ", gc_counter," garbage items (old proofs)\n");

}

//attempt to perform garbage collection for <count> schedules. If <count> is 0, attempt to perform garbage collection for all
void bridge::gc_schedules(name chain, int count){
  
  time_point cts = current_time_point();

  chainschedulestable _schedulestable(_self, chain.value);

  int distance = std::distance(_schedulestable.begin(), _schedulestable.end());

  //we always keep at least the last 2 schedules
  if (distance<=2) return;

  auto expiry_index = _schedulestable.get_index<"expiry"_n>();

  if (count == 0 ) count = distance;

  int counter = 0;
  int gc_counter = 0;

  do {

    auto e_itr = expiry_index.begin();

    //we always keep at least the last 2 schedules, otherwise we can delete the oldest schedule 
    if (distance > 2 && cts > e_itr->expiry){
      expiry_index.erase(e_itr);
      gc_counter++;
      distance--;
    } else break;
 
    counter++;
  } while (counter<count) ;

  if (gc_counter>0) print("collected ", gc_counter," garbage items (old schedules)\n");

}

//save a successfully proven block's merkle root to contract's RAM
void bridge::add_proven_root(name chain, uint32_t block_num, checksum256 root){

  time_point cts = current_time_point();

  uint64_t expiry = cts.sec_since_epoch() + (3600 * 24); //one day-minimum caching

  proofstable _proofstable(_self, chain.value);

  auto merkle_index = _proofstable.get_index<"merkleroot"_n>();

  auto itr = merkle_index.find(root);

  if (itr == merkle_index.end()){

    _proofstable.emplace( get_self(), [&]( auto& p ) {
      p.id = _proofstable.available_primary_key();
      p.block_height = block_num;
      p.block_merkle_root = root; 
      p.expiry =  time_point(seconds(expiry)) ;
    });

  }
  else {

    merkle_index.modify(itr, get_self(), [&]( auto& p ) {
      p.expiry =  time_point(seconds(expiry)) ;
    });

  }

  print("emplaced new proof-> height : ", block_num, ", root : ", root, "\n");


}

void bridge::check_proven_root(name chain, checksum256 root){

  proofstable _proofstable(_self, chain.value);

  check(_proofstable.begin() != _proofstable.end(), "no root has been proved yet");

  auto merkle_index = _proofstable.get_index<"merkleroot"_n>();

  auto itr = merkle_index.find(root);

  check(itr!=merkle_index.end(), "unknown merkle root. must prove root first");

}

name bridge::get_chain_name(checksum256 chain_id){

  auto cid_index = _chainstable.get_index<"chainid"_n>();
  auto chain_itr = cid_index.find(chain_id);

  check(chain_itr!=cid_index.end(), "chain not found");

  return chain_itr->name;

}

ACTION bridge::init(name chain_name, checksum256 chain_id,  schedule initial_schedule ) {

  require_auth(_self);

  auto chain_itr = _chainstable.find(chain_name.value);
  check(chain_itr==_chainstable.end(), "chain name already present");

  std::vector<char> serializedSchedule = pack(initial_schedule);

  // add new chain to chains table
  _chainstable.emplace( get_self(), [&]( auto& c ) {
    c.name = chain_name;
    c.chain_id = chain_id;
  });

  time_point cts = current_time_point();

  uint64_t expiry = cts.sec_since_epoch() + (3600 * 24); //One day-minimum caching

  chainschedulestable _schedulestable(_self, chain_name.value);
  _schedulestable.emplace( get_self(), [&]( auto& c ) {
    c.version = initial_schedule.version;
    c.producer_schedule = initial_schedule;
    c.hash = sha256(serializedSchedule.data(), serializedSchedule.size());
    c.first_block = 0;
    c.last_block = ULONG_MAX;
    c.expiry = time_point(seconds(expiry));
  });

}

bool bridge::checkactionproof(heavyproof blockproof, actionproof actionproof){

  //Prove action

  std::vector<char> serializedAction = pack(actionproof.action);
  checksum256 actionDigest = sha256(serializedAction.data(), serializedAction.size());

  check(actionDigest == actionproof.receipt.act_digest, "digest of action doesn't match the digest in action_receipt");

  std::vector<char> serializedReceipt = pack(actionproof.receipt);
  checksum256 receiptDigest = sha256(serializedReceipt.data(), serializedReceipt.size());

  check(actionproof.amproofpath.size() > 0, "must provide action proof path");

  if (actionproof.amproofpath.size() == 1 && actionproof.amproofpath[0] == receiptDigest){
    check(blockproof.blocktoprove.block.header.action_mroot == receiptDigest, "invalid action merkle proof path");
  }
  else check(proof_of_inclusion(actionproof.amproofpath, receiptDigest, blockproof.blocktoprove.block.header.action_mroot), "invalid action merkle proof path");
  
  print("action inclusion ", actionDigest, " successfully proved", "\n");

  return true;
  
}

bool bridge::checkblockproof(heavyproof blockproof){

  auto cid_index = _chainstable.get_index<"chainid"_n>();
  auto chain_itr = cid_index.find(blockproof.chain_id);

  check(chain_itr != cid_index.end(), "chain not supported");

  chainschedulestable _schedulestable(_self, chain_itr->name.value);
  auto sched_itr = _schedulestable.find(blockproof.blocktoprove.block.header.schedule_version);

  check(sched_itr != _schedulestable.end(), "schedule not supported");

  bridge::schedule producer_schedule = sched_itr->producer_schedule;
  checksum256 producer_schedule_hash = sched_itr->hash;

  auto block_num = blockproof.blocktoprove.block.header.block_num();

  //if current block_num is greater than the schedule's last block, change schedule
  if (block_num>sched_itr->last_block){

    sched_itr = _schedulestable.find(sched_itr->producer_schedule.version+1);

    check(sched_itr != _schedulestable.end(), "chain/schedule not supported");

    print("switched to newer schedule at block ", block_num ," (", sched_itr->producer_schedule.version, ").\n");

    producer_schedule = sched_itr->producer_schedule;
    producer_schedule_hash = sched_itr->hash;

  }

  //Prove block authenticity

  //must be active nodes prior to appending previous block's id
  uint64_t node_count = blockproof.blocktoprove.node_count;
  std::vector<checksum256> active_nodes = blockproof.blocktoprove.active_nodes; 
  
  print("active_nodes[active_nodes.size()-1] ", active_nodes[active_nodes.size()-1], "\n");

  checksum256 bm_root = check_block_header(blockproof.blocktoprove.block, active_nodes, node_count, producer_schedule, producer_schedule_hash);

  print("bm_root ", bm_root, "\n");

  add_proven_root(get_chain_name(blockproof.chain_id), block_num, bm_root);

  print("block authenticity has been proved\n");

  //Prove Range & Finality

  uint32_t schedule_version = blockproof.blocktoprove.block.header.schedule_version;

  uint32_t proof_range_start = block_num;
  uint32_t proof_range_end = blockproof.bftproof[blockproof.bftproof.size()-1].header.block_num();

  uint32_t range_span = proof_range_end-proof_range_start;
  uint32_t range_accounted = 0;

  print("range_span ", range_span, "\n");

  check(range_span <=336, "invalid range proof span");

  uint16_t numberOfBFTProofsRequiredPerRound = (uint16_t)fmin(ceil(2 * ((float)producer_schedule.producers.size() / 3)), producer_schedule.producers.size()) ;

  check(blockproof.bftproof.size()==numberOfBFTProofsRequiredPerRound*2, "invalid number of bft proofs");

  std::set<name> round1_bft_producers;
  std::set<name> round2_bft_producers;

  uint32_t current_height = proof_range_start;

  for (int i = 0 ; i < blockproof.bftproof.size(); i++){

    uint32_t bft_schedule_version = blockproof.bftproof[i].header.schedule_version;

    check(bft_schedule_version==schedule_version || bft_schedule_version==schedule_version+1, "invalid schedule version in BFT proof"); //can only have at most one schedule change over the time period required to prove an action

    uint32_t block_num = blockproof.bftproof[i].header.block_num();
    uint32_t difference = block_num - current_height;

    range_accounted+=difference;
  
    check(difference>=1 && difference <=12, "invalid range proof diff ");

    current_height = block_num;

    //if current block_num is greater than the schedule's last block, change schedule
    if (block_num>sched_itr->last_block){

      sched_itr = _schedulestable.find(sched_itr->producer_schedule.version+1);

      check(sched_itr != _schedulestable.end(), "chain/schedule not supported");

      print("switched to newer schedule at block ", block_num ," (", sched_itr->producer_schedule.version, ").\n");

      producer_schedule = sched_itr->producer_schedule;
      producer_schedule_hash = sched_itr->hash;

    }

    check_signatures(blockproof.bftproof[i].header.producer, blockproof.bftproof[i].producer_signatures, blockproof.bftproof[i].header.digest(), blockproof.bftproof[i].previous_bmroot,  producer_schedule, producer_schedule_hash );

    //print("BFT proof ", i," (block ", block_num, ") successfully proven \n");

    if (round1_bft_producers.size() == numberOfBFTProofsRequiredPerRound){
      //accumulating for second round

      if (round2_bft_producers.size() == 0) check( *round1_bft_producers.rbegin() != blockproof.bftproof[i].header.producer , "producer duplicated in bft proofs: " + blockproof.bftproof[i].header.producer.to_string());
      else check(round2_bft_producers.count(blockproof.bftproof[i].header.producer) == 0, "producer duplicated in bft proofs: " + blockproof.bftproof[i].header.producer.to_string());
      
      round2_bft_producers.emplace(blockproof.bftproof[i].header.producer);

      if (round2_bft_producers.size() == numberOfBFTProofsRequiredPerRound){
        
        //success, enough proofs for 2 rounds
        print("BFT finality successfully evaluated\n");
        print("  # of bft proofs evaluated: ", i + 1, "\n");
        break;

      }

    }
    else {
      //accumulating for first round

      check(round1_bft_producers.count(blockproof.bftproof[i].header.producer) == 0, "producer duplicated in bft proofs: " + blockproof.bftproof[i].header.producer.to_string());
      round1_bft_producers.emplace(blockproof.bftproof[i].header.producer);

    }

  }

  check(round1_bft_producers.size() == numberOfBFTProofsRequiredPerRound, "not enough BFT proofs to prove finality");
  check(round2_bft_producers.size() == numberOfBFTProofsRequiredPerRound, "not enough BFT proofs to prove finality");

  check(range_accounted<=range_span, "invalid range proof");

  //Unpack new schedule

  // if block header contains a new schedule, unpack and add it to schedules for chain
  if (blockproof.blocktoprove.block.header.header_extensions.size() > 0) {
    for (const auto& ext : blockproof.blocktoprove.block.header.header_extensions) {
      if (ext.first == 1) {
        auto new_schedule_hash_packed = ext.second;

        // unpack new schedule
        schedule new_producer_schedule = unpack<bridge::schedule>(new_schedule_hash_packed);
        auto schedule_hash = sha256(new_schedule_hash_packed.data(), new_schedule_hash_packed.size());

        // set end_block for previous schedule
        auto sched_itr = _schedulestable.find(new_producer_schedule.version-1);
        check(sched_itr!=_schedulestable.end(), "must prove missing schedules in correct sequence");

        _schedulestable.modify(sched_itr, get_self(), [&]( auto& c ) {
          c.last_block = blockproof.blocktoprove.block.header.block_num()-1;
        });

        sched_itr = _schedulestable.find(new_producer_schedule.version);

        // add it to schedules table if not already present
        if (sched_itr == _schedulestable.end()) {
          
          time_point cts = current_time_point();

          uint64_t expiry = cts.sec_since_epoch() + (3600 * 24); //One day-minimum caching

          _schedulestable.emplace( get_self(), [&]( auto& c ) {
            c.version = new_producer_schedule.version;
            c.producer_schedule = new_producer_schedule;
            c.hash = schedule_hash;
            c.first_block = blockproof.blocktoprove.block.header.block_num();
            c.last_block = ULONG_MAX;
            c.expiry = time_point(seconds(expiry)) ;
          });

          print("proved new schedule, hash: ", schedule_hash, "\n");


        }
      }
    }
  }

  //remove up to 2 proofs
  gc_proofs(chain_itr->name, 2);
  //remove up to 2 schedules
  gc_schedules(chain_itr->name, 2);

  return true;

}

ACTION bridge::checkproofa(heavyproof blockproof){

  checkblockproof(blockproof);
  
}

ACTION bridge::checkproofb(heavyproof blockproof, actionproof actionproof){

  checkblockproof(blockproof);
  checkactionproof(blockproof, actionproof);

}


ACTION bridge::checkproofc(lightproof blockproof, actionproof actionproof){

  check_proven_root(get_chain_name(blockproof.chain_id), blockproof.root);

  checksum256 headerDigest = blockproof.header.digest();
  checksum256 id = compute_block_id(headerDigest, blockproof.header.block_num());

  std::vector<char> serializedAction = pack(actionproof.action);
  std::vector<char> serializedReceipt = pack(actionproof.receipt);

  checksum256 action_digest = sha256(serializedAction.data(), serializedAction.size());
  checksum256 action_receipt_digest = sha256(serializedReceipt.data(), serializedReceipt.size());

  print("action_digest : ", action_digest, "\n");
  print("action_receipt_digest : ", action_receipt_digest, "\n");
  
  check(actionproof.receipt.act_digest == action_digest, "digest of action doesn't match the digest in action_receipt");

  if (actionproof.amproofpath.size() == 1 && actionproof.amproofpath[0] == action_receipt_digest){
    check(blockproof.header.action_mroot == action_receipt_digest, "invalid action merkle proof path");
  }
  else check(proof_of_inclusion(actionproof.amproofpath, action_receipt_digest, blockproof.header.action_mroot), "invalid action merkle proof path");
  
  print("id : ", id, "\n" );

  check(proof_of_inclusion(blockproof.bmproofpath, id, blockproof.root), "invalid block merkle proof");

  //success
  
}

ACTION bridge::test(int i){

}


ACTION bridge::test2(blockheader h){

}

ACTION bridge::clear( ) {
  
  require_auth(_self);

  while (_chainstable.begin() != _chainstable.end()) {
    auto chain_itr = _chainstable.end();
    chain_itr--;

    chainschedulestable _schedulestable(_self, chain_itr->name.value);
    while (_schedulestable.begin() != _schedulestable.end()) {
      auto itr = _schedulestable.end();
      itr--;
      _schedulestable.erase(itr);
    }

    proofstable _proofstable(_self, chain_itr->name.value);
    while (_proofstable.begin() != _proofstable.end()) {
      auto itr = _proofstable.end();
      itr--;
      _proofstable.erase(itr);
    }

    _chainstable.erase(chain_itr);
    
  }


}