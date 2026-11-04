/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rows the real recorder (tools/scripts/tip_agreement_probe.sh)
 *          wrote for the end-to-end cases of test_tip_agreement_judge.c,
 *          minus the leading "ts" key: eight rows per case, identical but
 *          for ts. Captured from the retired shell harness running the real
 *          recorder against fixture node readers, so the judge is graded on
 *          the recorder's own output and not on a hand-written imitation.
 *
 *   AGREE     two distinct remote hosts hold our hash at our tip
 *   CAPPED    thirteen qualifying clusters: the census hit the query cap
 *   SENTINEL  a valid one-witness sentinel row, no rival
 *   RIVAL     the same, with a four-witness rival retained at rank 12
 *   NOCOUNT   the sentinel row carried no usable count
 *   OVERSIZE  the sentinel count was out of range
 *   CNA       the source was unusable: could-not-ask */

#ifndef ZCL_TEST_TIP_AGREEMENT_JUDGE_ROWS_H
#define ZCL_TEST_TIP_AGREEMENT_JUDGE_ROWS_H

#define TJR_AGREE \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":3197949," \
    "\"our_tip_hash\":\"00000413d24a748e127ed332680da715e676b9a3d60c2f9d4b0dd592113a8a05\"," \
    "\"modal_remote_hash\":\"00000413d24a748e127ed332680da715e676b9a3d60c2f9d4b0dd592113a8a05\"," \
    "\"modal_remote_peers\":2," \
    "\"modal_remote_groups\":2," \
    "\"disagreeing_peers\":0," \
    "\"contested_peers\":0," \
    "\"rival_heights_unresolved\":0," \
    "\"heights_above_tip\":0," \
    "\"disagreeing_hashes\":[]," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":9," \
    "\"clusters_seen\":1," \
    "\"cluster_census_complete\":true," \
    "\"qualifying_cluster_census_complete\":true," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"agrees\"," \
    "\"reason\":\"our_hash_matches_2_distinct_remote_peers_at_3197949\"," \
    "\"error_detail\":\"\"}"

#define TJR_CAPPED \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":null," \
    "\"our_tip_hash\":\"\"," \
    "\"modal_remote_hash\":\"\"," \
    "\"modal_remote_peers\":null," \
    "\"modal_remote_groups\":null," \
    "\"disagreeing_peers\":null," \
    "\"contested_peers\":null," \
    "\"rival_heights_unresolved\":null," \
    "\"heights_above_tip\":null," \
    "\"disagreeing_hashes\":null," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":null," \
    "\"clusters_seen\":13," \
    "\"cluster_census_complete\":false," \
    "\"qualifying_cluster_census_complete\":false," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"could-not-ask\"," \
    "\"reason\":\"remote_observations_cluster_limit_reached\"," \
    "\"error_detail\":\"at least 13 clusters returned; qualifying rival census incomplete\"}"

#define TJR_SENTINEL \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":3197949," \
    "\"our_tip_hash\":\"0000000000000000000000000000000000000000000000000000000000000001\"," \
    "\"modal_remote_hash\":\"0000000000000000000000000000000000000000000000000000000000000001\"," \
    "\"modal_remote_peers\":15," \
    "\"modal_remote_groups\":2," \
    "\"disagreeing_peers\":null," \
    "\"contested_peers\":0," \
    "\"rival_heights_unresolved\":0," \
    "\"heights_above_tip\":null," \
    "\"disagreeing_hashes\":null," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":40," \
    "\"clusters_seen\":13," \
    "\"cluster_census_complete\":false," \
    "\"qualifying_cluster_census_complete\":true," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"agrees\"," \
    "\"reason\":\"our_hash_matches_15_distinct_remote_peers_at_3197949\"," \
    "\"error_detail\":\"\"}"

#define TJR_NOCOUNT \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":null," \
    "\"our_tip_hash\":\"\"," \
    "\"modal_remote_hash\":\"\"," \
    "\"modal_remote_peers\":null," \
    "\"modal_remote_groups\":null," \
    "\"disagreeing_peers\":null," \
    "\"contested_peers\":null," \
    "\"rival_heights_unresolved\":null," \
    "\"heights_above_tip\":null," \
    "\"disagreeing_hashes\":null," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":null," \
    "\"clusters_seen\":13," \
    "\"cluster_census_complete\":false," \
    "\"qualifying_cluster_census_complete\":false," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"could-not-ask\"," \
    "\"reason\":\"remote_observations_cluster_limit_reached\"," \
    "\"error_detail\":\"sentinel row shape or count invalid; qualifying rival census unknown\"}"

#define TJR_OVERSIZE \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":null," \
    "\"our_tip_hash\":\"\"," \
    "\"modal_remote_hash\":\"\"," \
    "\"modal_remote_peers\":null," \
    "\"modal_remote_groups\":null," \
    "\"disagreeing_peers\":null," \
    "\"contested_peers\":null," \
    "\"rival_heights_unresolved\":null," \
    "\"heights_above_tip\":null," \
    "\"disagreeing_hashes\":null," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":null," \
    "\"clusters_seen\":13," \
    "\"cluster_census_complete\":false," \
    "\"qualifying_cluster_census_complete\":false," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"could-not-ask\"," \
    "\"reason\":\"remote_observations_cluster_limit_reached\"," \
    "\"error_detail\":\"sentinel row shape or count invalid; qualifying rival census unknown\"}"

#define TJR_CNA \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":null," \
    "\"our_tip_hash\":\"\"," \
    "\"modal_remote_hash\":\"\"," \
    "\"modal_remote_peers\":null," \
    "\"modal_remote_groups\":null," \
    "\"disagreeing_peers\":null," \
    "\"contested_peers\":null," \
    "\"rival_heights_unresolved\":null," \
    "\"heights_above_tip\":null," \
    "\"disagreeing_hashes\":[]," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":null," \
    "\"clusters_seen\":null," \
    "\"cluster_census_complete\":false," \
    "\"qualifying_cluster_census_complete\":false," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"could-not-ask\"," \
    "\"reason\":\"remote_observations_unavailable\"," \
    "\"error_detail\":\"no_reply\"}"

#define TJR_RIVAL \
    "\"instance\":\"canonical\"," \
    "\"rpcport\":18232," \
    "\"datadir\":\"/fixture/canonical\"," \
    "\"window_secs\":900," \
    "\"min_distinct_peers\":2," \
    "\"our_height\":3197949," \
    "\"height\":3197949," \
    "\"our_tip_hash\":\"0000000000000000000000000000000000000000000000000000000000000001\"," \
    "\"modal_remote_hash\":\"0000000000000000000000000000000000000000000000000000000000000001\"," \
    "\"modal_remote_peers\":15," \
    "\"modal_remote_groups\":2," \
    "\"disagreeing_peers\":null," \
    "\"contested_peers\":4," \
    "\"rival_heights_unresolved\":0," \
    "\"heights_above_tip\":null," \
    "\"disagreeing_hashes\":null," \
    "\"peers_total\":21," \
    "\"peers_with_height\":20," \
    "\"peers_usable\":40," \
    "\"clusters_seen\":13," \
    "\"cluster_census_complete\":false," \
    "\"qualifying_cluster_census_complete\":true," \
    "\"excluded_hosts\":0," \
    "\"outcome\":\"agrees\"," \
    "\"reason\":\"our_hash_matches_15_distinct_remote_peers_at_3197949\"," \
    "\"error_detail\":\"\"}"

#endif /* ZCL_TEST_TIP_AGREEMENT_JUDGE_ROWS_H */
