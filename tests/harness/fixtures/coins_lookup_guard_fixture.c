/* Fixture for test_make_lint_gates: a controller file that introduces a
 * coins_view_cache_get_coins call without the guard. */

#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/uint256.h"

int coins_lookup_guard_fixture(struct coins_view_cache *cache,
                               const struct uint256 *txid)
{
    struct coins c;
    coins_init(&c);
    int found = coins_view_cache_get_coins(cache, txid, &c) ? 1 : 0;
    coins_free(&c);
    return found;
}
