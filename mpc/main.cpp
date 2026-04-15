#include <cmath>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "secure_type/secure_unsigned_integer.h"

namespace program_options = boost::program_options;

namespace mo = encrypto::motion;

bool CheckPartyArgumentSyntax(const std::string &party_argument);

std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char *av[]);

mo::PartyPointer CreateParty(const program_options::variables_map &user_options);

int EvaluateProtocol(const mo::PartyPointer &party, uint64_t my_cards, uint32_t my_randomness,
                     uint64_t community_cards);


int main(int ac, char *av[]) {
    auto [user_options, help_flag] = ParseProgramOptions(ac, av);
    // if help flag is set - print allowed command line arguments and exit
    if (help_flag) return EXIT_SUCCESS;

    mo::PartyPointer party = CreateParty(user_options);

    const uint64_t my_cards = user_options["my-cards"].as<std::uint64_t>();
    const uint32_t my_randomness = user_options["my-cards"].as<std::uint32_t>();
    const uint64_t community_cards = user_options["community-cards"].as<std::uint64_t>();

    const uint64_t new_community_card = EvaluateProtocol(party, my_cards, my_randomness, community_cards);

    std::cout << "Next community cards is " << new_community_card;
    return EXIT_SUCCESS;
}

int EvaluateProtocol(const mo::PartyPointer &party, const uint64_t my_cards, const uint32_t my_randomness,
                     uint64_t community_cards) {
    const std::size_t number_of_parties{party->GetConfiguration()->GetNumOfParties()};

    std::vector<mo::SecureUnsignedInteger> players_cards(number_of_parties), players_randomness(number_of_parties),
            players_community_cards(number_of_parties);

    for (std::size_t i = 0; i < number_of_parties; ++i) {
        players_cards[i] = party->In<mo::MpcProtocol::kBmr>(my_cards, i);
        players_randomness[i] = party->In<mo::MpcProtocol::kBmr>(my_randomness, i);
        players_community_cards[i] = party->In<mo::MpcProtocol::kBmr>(community_cards, i);
    }


    // TODO: Check if all community cards are the same

    mo::SecureUnsignedInteger availability_vector = players_community_cards[0];
    mo::SecureUnsignedInteger final_randomness = mo::SecureUnsignedInteger();


    for (std::size_t i = 0; i < number_of_parties; i++) {
        // remove used cards from the availability vector for the next card
        availability_vector = players_cards[i].Get() & availability_vector.Get();
        // XOR all players randomness
        final_randomness = players_randomness[i].Get() ^ final_randomness.Get();
    }


    auto indices = availability_vector->Split();


    std::vector<mo::SecureUnsignedInteger> available_indexes;




    auto next_card = available_indexes[final_randomness.Get() % std::size(available_indexes)].Out();

    // put your code here
    party->Run();
    party->Finish();

    return 0;
}

// <variables map, help flag>
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char *av[]) {
    using namespace std::string_view_literals;
    constexpr std::string_view kConfigFileMessage =
            "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
    bool print, help;
    program_options::options_description description("Allowed options");
  // clang-format off
    description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("my-cards", program_options::value<uint64_t>()->required(), "player's cards")
      ("my-randomness", program_options::value<uint32_t>(), "my randomness")
      ("community-cards", program_options::value<uint64_t>()->required(), "community cards");
    // clang-format on

    program_options::variables_map user_options;

    program_options::store(program_options::parse_command_line(ac, av, description), user_options);
    program_options::notify(user_options);

    // argument help or no arguments (at least a configuration file is expected)
    if (user_options["help"].as<bool>() || ac == 1) {
        std::cout << description << "\n";
        return std::make_pair<program_options::variables_map, bool>({}, true);
    }

    // read configuration file
    if (user_options.contains("configuration-file")) {
        std::ifstream ifs(user_options["configuration-file"].as<std::string>().c_str());
        program_options::variables_map user_option_config_file;
        program_options::store(program_options::parse_config_file(ifs, description), user_options);
        program_options::notify(user_options);
    }

    // print parsed parameters
    if (user_options.contains("my-id")) {
        if (print) std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
    } else
        throw std::runtime_error("My id is not set but required");

    if (user_options.contains("parties")) {
        const std::vector<std::string> other_parties{
            user_options["parties"].as<std::vector<std::string> >()
        };
        std::string parties("Other parties: ");
        for (auto &p: other_parties) {
            if (CheckPartyArgumentSyntax(p)) {
                if (print) parties.append(" " + p);
            } else {
                throw std::runtime_error("Incorrect party argument syntax " + p);
            }
        }
        if (print) std::cout << parties << std::endl;
    } else
        throw std::runtime_error("Other parties' information is not set but required");

    return std::make_pair(user_options, help);
}

const std::regex kPartyArgumentRegex(R"((\d+),(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(\d{1,5}))");

bool CheckPartyArgumentSyntax(const std::string &party_argument) {
    // other party's id, IP address, and port
    return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string &party_argument) {
    std::smatch match;
    std::regex_match(party_argument, match, kPartyArgumentRegex);
    auto id = boost::lexical_cast<std::size_t>(match[1]);
    auto host = match[2];
    auto port = boost::lexical_cast<std::uint16_t>(match[3]);
    return {id, host, port};
}

mo::PartyPointer CreateParty(const program_options::variables_map &user_options) {
    const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
    const auto number_of_parties{parties_string.size()};
    const auto my_id{user_options["my-id"].as<std::size_t>()};
    if (my_id >= number_of_parties) {
        throw std::runtime_error(fmt::format(
            "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
            my_id, number_of_parties));
    }

    mo::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

    for (const auto &party_string: parties_string) {
        const auto [party_id, host, port] = ParsePartyArgument(party_string);
        if (party_id >= number_of_parties) {
            throw std::runtime_error(
                fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                            "is {} and #parties is {}",
                            party_id, number_of_parties));
        }
        parties_configuration.at(party_id) = std::make_pair(host, port);
    }
    mo::communication::TcpSetupHelper helper(my_id, parties_configuration);
    auto communication_layer = std::make_unique<mo::communication::CommunicationLayer>(
        my_id, helper.SetupConnections());
    auto party = std::make_unique<mo::Party>(std::move(communication_layer));
    auto configuration = party->GetConfiguration();
    // disable logging if the corresponding flag was set
    const auto logging{!user_options.contains("disable-logging")};
    configuration->SetLoggingEnabled(logging);
    return party;
}
