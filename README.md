### Decentralized P2P Texas Poker

## Introduction

For many years Mental Poker remained an unsolved cryptography puzzle. There are multiple solutions for the Poker game
but there is no drop-tolerant complete solution out there that solves all the problems and abstract away the complexity
of the game from the end users. Multiple papers suggest partial solutions for the poker game but no one is practical.

## The problem

One of the most frequently cited solution is to use a shuffle-prove algorithm to allow each player to shuffle and add
their encryption to the deck of cards. After the deck is shuffled and encrypted nobody knows the permutation of the deck
and the deck is encrypted with each player keys so is impossible to know the cards and their permutation. Each player
receives their encrypted cards and then ask other players to remove their encryption from the cards. At the end he will
remove his encryption layer from the cards and he will be able to read his cards.
Players also needs to collaborate in order to decrypt the next publicly available community cards.

This model works well for the problem of dealing the cards in a trustless manner, but the biggest problem is that the
protocol is not drop-tolerant. If the one of the player doesn't like his cards he refuse to participate in the protocol
anymore and the game could not continue anymore because the remaining cards are encrypted. The problem could be caused
by malicious players or by honest players that simply have technical problems.
Possible solutions for this problems are mostly economic. The player that refuse to participate in the protocol anymore
is slashed, but this is far from being a perfect solution. If one player has a very good hand he will not be happy to
receive a very small compensation if one malicious/unlucky player drops in the middle of the game.

In the following section I will describe a complete solution to these problems and a complete implementation for the
Mental (Texas) Poker game.

## Dealing cards

### Phase 1 - Hole cards

Same as before, players will run a shuffle-prove algorithm (Bayer-Groth) to shuffle and encrypt a deck of cards. After
each player shuffle and add their encryption layer, proving the correct execution of the protocol, we can deal each
cards to the players. For the `N` players, the first `2*N` cards will be available for the players. Player `i` cards
will be the cards at position `2*i+0` and `2*i+1` .
Each player will ask every other players to remove their decryption layer and he will be the last player that decrypt
the encrypted cards so he is the only one that know the value. Each player will remove the encryption from other players
cards.

If any player exit before the finalization of card decryption then the player will be slashed and the shuffling need to
start over. The slashing mechanism should be incremental, if the same player drops multiple session in a raw he will be
slashed more. Note that if any player drops at this point there is no strategic loss for the other players because no
cards are decrypted yet.

So far the protocol is very similar with the most common solution, described in the introduction section.

After each player receive their cards and they remove the encryption from the cards they could throw out the encrypted
deck and the game is now drop tolerant, each player could exit at any time.
The shuffle-prove algorithm is used just to deal cards to the players in a random and trustless way.

Each user will commit to his cards and they will post the commitment on-chain.

### Phase 2 - Community Cards (flop, turn, river)

Players need to select the community cards, starting with the first 3 cards for the flop. These cards needs to be
selected based on good randomness and the cards need to be available for every player. Another important thing is that
community cards should be unique and duplicates should not be possible, either from the already selected community cards
or from the cards that are in the players hand already. For this problem we need to use MPC (secure Multi Party
Computation).

Each player will initialize the availability vector which is a bit vector `D` of length 52 (size of the deck) and he
will fill out the vector with value `1` except for the position of his cards. For the two cards that he own he needs to
mark the cards unavailable in the vector, so he will set the value to 0. This vector represents the available cards for
the next card that will be deal.
For this phase user will also generate a ZK proof to prove that he done this step without cheating. The proof is small
and fast to generate due to the small computation that he needs to prove. The proof will also be cheap to verify

Example:  `D_{i} = [1,1,1,1,1,0,1,1,...0,1,1]` availability vector for player `i`

The game will store a public availability vector for the community cards on-chain. Each community cards will be marked
unavailable in the vector.

#### Randomness

The next phase is to get public randomness. The game will select the block hash of a block ahead of time, for example
100 blocks from now. This way it will be hard to predict ahead of time what the block hash will be. Each users could add
their own randomness to increase the entropy.

## MPC

Players will run the SPDZ MPC (Multi Party Computation) protocol to select the next community card.
The communication is p2p using [webSPDZ](https://github.com/tbuchs/webSPDZ)
SPZ is very fast and such small computation is expected to take less then 1 second.

Public inputs:

- `block_hash` - for randomness
- `availability_cards` - publicly availability vector.
- `availability_cards_user_{i}` - each user availability cards (private)
- `user_randomness` - extra randomness to increase the entropy

The MPC algorithm will perform an `AND` operation for all the availability vectors, the private users vectors and the
public community vectors and then will select the next community card by choosing an available index depending on the
randomness.

No information is revealed and no user could cheat. Only the public inputs and the output is known.

There will be 3 MPC sessions. First session (flop) will select 3 cards, and the following 2 sessions will each select
one card.

If any players drop in this phase the game is not affected and could continue without him.

## Starknet

The whole logic of the game will be managed by the on-chain smart-contract. Users will lock their funds into a smart
contract when they join a poker table.
Cards commitment and each player action (call, bet, raise, fold) needs to be performed on-chain.

Starknet has huge advantage in terms of speed and costs. Each transaction is confirmed in ~2 seconds and the gas cost is
very cheap