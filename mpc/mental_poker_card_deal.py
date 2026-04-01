from Compiler import program
from Compiler.library import print_ln
from Compiler.util import bit_and, bit_xor

community_cards_availability = int(program.args[1])

# all 52 bits set to 1
# MAX = 4503599627370495
# test(community_cards_availability <= MAX, 1)

# Number of players
n = int(program.args[2])
print_ln('Number of players %s', n)

players_randomness = 0


@for_range(n)
def remove_unavailable_cards(i):
    player_i = program.args[2 + i]
    player_i_availability = player_i.0
    player_i_randomness = player_i.1
    # test(player_i_availability <= MAX, 1)
    community_cards_availability = bit_and(
        community_cards_availability, player_i_availability)
    players_randomness = bit_xor(players_randomness, player_i_randomness)


cards_availability_arr = sint.Array([i for i, val in enumerate(
    community_cards_availability.bit_decompose(52)) if val == 1])
next_community_card = cards_availability_arr[players_randomness % len(
    cards_availability_arr)]

print_ln('Next community card %s', next_community_card.reveal())
