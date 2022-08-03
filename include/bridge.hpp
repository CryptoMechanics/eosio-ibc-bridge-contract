


#include <eosio/eosio.hpp>
#include <eosio/system.hpp>
#include <eosio/producer_schedule.hpp>
#include <math.h>

using namespace eosio;



CONTRACT bridge : public contract {
   public:
      using contract::contract;

		static uint32_t reverse_bytes(uint32_t input){

		  int32_t output = (input>>24 & 0xff)|(input>>8 & 0xff00)|(input<<8 & 0xff0000)|(input<<24 & 0xff000000);

		  return output;

		}


		static checksum256 compute_block_id(checksum256 hash, uint32_t block_num) { 

		  uint8_t fullraw[32] = {0};

		  uint32_t r_block_num = reverse_bytes(block_num);

		  std::array<uint8_t, 32> ab =  hash.extract_as_byte_array();

		  memcpy(&fullraw[0], (uint8_t *)&r_block_num, 4);

		  for (int i = 4; i <32; i++){
		    memcpy(&fullraw[i], (uint8_t *)&ab[i], 1);
		  }

		  return checksum256(fullraw);

		}

		static uint32_t get_block_num_from_id(checksum256 id) {
		  
		  std::array<uint8_t, 32> ab =  id.extract_as_byte_array();

		  uint32_t block_num = ab[3] | (ab[2] << 8) | (ab[1] << 16) | (ab[0] << 24);

		  return block_num;

		}


		//Adding definition to ABI file to make it easier to interface with the contract
		TABLE schedule {
				 
			uint32_t version;
			std::vector<producer_authority> producers ;

			EOSLIB_SERIALIZE( schedule, (version)(producers))

		};

      TABLE blockheader {

			block_timestamp	timestamp;

			name				producer;
			
			uint16_t		confirmed;
			
			checksum256 previous; 
			checksum256 transaction_mroot;
			checksum256 action_mroot;
			
			uint32_t 		schedule_version;

			std::optional<producer_schedule>  new_producers;

			std::vector<std::pair<uint16_t,std::vector<char>>> header_extensions;

			checksum256 digest() const {
			  
			  std::vector<char> serializedFull = pack(*this);
			  checksum256 hFull = sha256(serializedFull.data(), serializedFull.size());

			  return hFull;

			}

      	uint32_t block_num()const { return get_block_num_from_id(previous) + 1; }
      	checksum256 block_id()const { return compute_block_id(digest() , block_num()); }


      	EOSLIB_SERIALIZE( blockheader, (timestamp)(producer)(confirmed)(previous)(transaction_mroot)(action_mroot)(schedule_version)(new_producers)(header_extensions))

      };

/*      //hashed block header
      TABLE hblockheader {
      	
      	uint32_t 					block_num;
      	name 							producer;
			std::vector<signature> 	producer_signatures;
      	checksum256 				header_digest;
      	checksum256  				previous_bmroot;

			EOSLIB_SERIALIZE( hblockheader, (block_num)(producer)(producer_signatures)(header_digest)(previous_bmroot))

      };
*/
      //signed block header
      TABLE sblockheader {
      	
      	blockheader 				header;

			std::vector<signature> 	producer_signatures;

      	checksum256  				previous_bmroot;

			EOSLIB_SERIALIZE( sblockheader, (header)(producer_signatures)(previous_bmroot))

      };

		//structure holding a full block header, as well as incremental merkle tree data (active_nodes and nodes_count)
		TABLE anchorblock {
				 
			sblockheader block;
			std::vector<checksum256> active_nodes;
			uint64_t node_count;

			EOSLIB_SERIALIZE( anchorblock, (block)(active_nodes)(node_count))

		};

      TABLE authseq {
      	name account;
      	uint64_t sequence;

      	EOSLIB_SERIALIZE( authseq, (account)(sequence) )

      };

		TABLE actreceipt {
			name                    							receiver;
			checksum256             							act_digest; 
			uint64_t                							global_sequence = 0;
			uint64_t                							recv_sequence   = 0;
			    
			std::vector<authseq> 								auth_sequence;
			unsigned_int            							code_sequence = 0;
			unsigned_int            							abi_sequence  = 0;

			EOSLIB_SERIALIZE( actreceipt, (receiver)(act_digest)(global_sequence)(recv_sequence)(auth_sequence)(code_sequence)(abi_sequence) )

		};

		typedef std::vector<checksum256> checksum256_list; // required because nested vectors not support in legacy CDTs

/*		TABLE bmproof {
			std::vector<checksum256_list> 	proofs;
			std::vector<checksum256> 			leaves;
			checksum256 							root;

			EOSLIB_SERIALIZE( bmproof, (proofs)(leaves)(root))

		};*/

		//heavy proof
		TABLE heavyproof {

			checksum256												chain_id;

			anchorblock 											blocktoprove;

			std::vector<sblockheader>							bftproof;

			EOSLIB_SERIALIZE( heavyproof, (chain_id)(blocktoprove)(bftproof))

		};

		TABLE lightproof {

			checksum256												chain_id;

			blockheader    										header;

			std::vector<checksum256>  							bmproofpath;

			EOSLIB_SERIALIZE( lightproof, (chain_id)(header)(bmproofpath))

		};

		TABLE actionproof {

			action 													action;
			actreceipt 												receipt;

			std::vector<checksum256>							amproofpath;

			EOSLIB_SERIALIZE( actionproof, (action)(receipt)(amproofpath))

		};

/*		TABLE validproof {

			uint64_t												id;
			action 													action;
			checksum256											chain_id;
			checksum256 										receipt_digest;
			name 											  		prover;

     		uint64_t primary_key()const { return id; }
     		checksum256 by_digest()const { return receipt_digest; }

			EOSLIB_SERIALIZE( validproof, (id)(action)(chain_id)(receipt_digest)(prover))

		};*/

		// unscoped, stores readable name and chain id for supported chains
		TABLE chain {

			name name;
			checksum256 chain_id;

			uint64_t primary_key()const { return name.value; }
			checksum256 by_chain_id()const { return chain_id; }

			EOSLIB_SERIALIZE( chain, (name)(chain_id) )

		};

		// scoped by readable chain name
		TABLE chainschedule {

			uint64_t id;
			schedule producer_schedule;
			checksum256 hash;
			uint64_t last_block;

			uint64_t primary_key()const { return id; }

			EOSLIB_SERIALIZE( chainschedule, (id)(producer_schedule)(hash)(last_block) )

		};

		TABLE lastproof {

			uint64_t 		id;

			checksum256		chain_id;
			uint32_t 		block_height;
			
			checksum256 	block_merkle_root;

			time_point 		expiry;

			uint64_t primary_key()const { return id; }
			checksum256 by_chain_id()const { return chain_id; }
			uint64_t by_block_height()const { return block_height; }
			checksum256 by_merkle_root()const { return block_merkle_root; }
			uint64_t by_expiry()const { return expiry.sec_since_epoch(); }

			EOSLIB_SERIALIZE( lastproof, (id)(chain_id)(block_height)(block_merkle_root)(expiry) )

		};
		
		
	    typedef eosio::multi_index< "chains"_n, chain,
	    		indexed_by<"chainid"_n, const_mem_fun<chain, checksum256, &chain::by_chain_id>>> chainstable;

	    typedef eosio::multi_index< "schedules"_n, chainschedule> chainschedulestable;

/*	    typedef eosio::multi_index< "proofs"_n, validproof,
            indexed_by<"digest"_n, const_mem_fun<validproof, checksum256, &validproof::by_digest>>> proofstable;*/

	    typedef eosio::multi_index< "lastproofs"_n, lastproof,
            indexed_by<"chainid"_n, const_mem_fun<lastproof, checksum256, &lastproof::by_chain_id>>,
            indexed_by<"height"_n, const_mem_fun<lastproof, uint64_t, &lastproof::by_block_height>>,
            indexed_by<"merkleroot"_n, const_mem_fun<lastproof, checksum256, &lastproof::by_merkle_root>>,
            indexed_by<"expiry"_n, const_mem_fun<lastproof, uint64_t, &lastproof::by_expiry>>> proofstable;

      chainstable _chainstable;
   	proofstable _proofstable;

	    bridge( name receiver, name code, datastream<const char*> ds ) :
	    contract(receiver, code, ds),
	    _chainstable(receiver, receiver.value),
	    _proofstable(receiver, receiver.value)
	    {
	    
	    }

      ACTION init(name chain_name, checksum256 chain_id, schedule initial_schedule );

      //Two different proving schemes are available.

      ACTION checkproofa(name prover, heavyproof blockproof);
      ACTION checkproofb(name prover, heavyproof blockproof, actionproof actionproof);
      ACTION checkproofc(name prover, lightproof blockproof, actionproof actionproof); 
      
      ACTION clear();

		void gc_proofs(int count);

		bool checkblockproof(heavyproof blockproof);
		bool checkactionproof(heavyproof blockproof, actionproof actionproof);

		void add_proven_root(checksum256 chain_id, uint32_t block_num, checksum256 root);
		checksum256 get_proven_root();

};