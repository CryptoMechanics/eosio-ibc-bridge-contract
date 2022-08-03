project(bridge)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_contract( bridge bridge bridge.cpp )
target_include_directories( bridge PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( bridge ${CMAKE_SOURCE_DIR}/../ricardian )