#include "RelayServer.h"
#include "events.h"

struct AuthMessage {
    std::string content;
    unsigned created_at;
    std::string id;
    unsigned kind;
    std::string pubkey;
    std::string sig;
    std::vector<std::vector<std::string>> tags;
};

struct relayURL {
    std::string url;
    unsigned port;
};


std::string hex2bin(const std::string& hex) {
    std::string bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        bytes += byte;
    }
    return bytes;
}

bool isWithinLimit(unsigned timestamp, int minutes) {
    // get current time as unix timestamp
    auto now = std::chrono::system_clock::now();
    auto now_as_time_t = std::chrono::system_clock::to_time_t(now);
    unsigned now_as_unix_timestamp = static_cast<unsigned>(now_as_time_t);

    int diff_in_seconds = std::abs(static_cast<int>(now_as_unix_timestamp - timestamp));
    return diff_in_seconds <= minutes * 60;
}

std::string urlToIP(const std::string& url) {
    struct hostent* he;
    struct in_addr** addr_list;
    if ((he = gethostbyname(url.c_str())) == NULL) { 
        // get the host info
        perror("gethostbyname");
        return "";
    }

    addr_list = (struct in_addr**)he->h_addr_list;

    //Return the first one;
    if (addr_list[0] != NULL) {
        return inet_ntoa(*addr_list[0]);
    }

    return "";
}

relayURL ParseRelayURL(const std::string& fullUrl) {
    relayURL relay;

    // Extract URL and port
    std::size_t protocol_pos = fullUrl.find("ws://");
    std::size_t port_pos = fullUrl.find_last_of(":");
    if (protocol_pos == std::string::npos || port_pos == std::string::npos || port_pos <= protocol_pos) {
        throw std::runtime_error("URL is not in the format \"ws://url:port\"");
    }

    std::string url = fullUrl.substr(protocol_pos + 5, port_pos - protocol_pos - 5);
    unsigned port = std::stoul(fullUrl.substr(port_pos + 1));

    std::string ip = urlToIP(url);
    if (ip.empty()) {
        throw std::runtime_error("Could not resolve IP for " + url);
    }

    relay.url = ip;
    relay.port = port;

    return relay;
}

AuthMessage ParseAuthMessage(const tao::json::value& val) {
    AuthMessage auth;

    if (!val.is_object()) throw std::runtime_error("Message is not an object");

    if (!val.at("content").is_string()) throw std::runtime_error("content is not a string");
    auth.content = val.at("content").get_string();

    if (!val.at("created_at").is_unsigned()) throw std::runtime_error("created_at is not an unsigned");
    auth.created_at = val.at("created_at").get_unsigned();

    if (!val.at("id").is_string()) throw std::runtime_error("id is not a string");
    auth.id = val.at("id").get_string();

    if (!val.at("kind").is_unsigned()) throw std::runtime_error("kind is not an unsigned");
    auth.kind = val.at("kind").get_unsigned();

    if (!val.at("pubkey").is_string()) throw std::runtime_error("pubkey is not a string");
    auth.pubkey = val.at("pubkey").get_string();

    if (!val.at("sig").is_string()) throw std::runtime_error("sig is not a string");
    auth.sig = val.at("sig").get_string();

    if (!val.at("tags").is_array()) throw std::runtime_error("tags is not an array");
    for(const auto& tag_pair : val.at("tags").get_array()) {
        if (!tag_pair.is_array() || tag_pair.get_array().size() != 2) throw std::runtime_error("bad tag pair");
        std::vector<std::string> tag;
        for(const auto& tag_element : tag_pair.get_array()) {
            if (!tag_element.is_string()) throw std::runtime_error("tag element is not a string");
            tag.push_back(tag_element.get_string());
        }
        auth.tags.push_back(tag);
    }

    // Debug output
    std::cout << "Content: " << auth.content << "\n";
    std::cout << "Created at: " << auth.created_at << "\n";
    std::cout << "ID: " << auth.id << "\n";
    std::cout << "Kind: " << auth.kind << "\n";
    std::cout << "Public key: " << auth.pubkey << "\n";
    std::cout << "Signature: " << auth.sig << "\n";
    for (const auto &tag : auth.tags) {
        std::cout << "Tag " << tag[0] << ": " << tag[1] << "\n";
    }

    return auth;
}


void RelayServer::runIngester(ThreadPool<MsgIngester>::Thread &thr) {
    secp256k1_context *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    Decompressor decomp;

    //DEBUG
    authorizePubKey("ecb4a5ed737920fee9206fa73e1b4a8ac473e618ea45a73af19706db6213b80e");

    while(1) {
        auto newMsgs = thr.inbox.pop_all();

        auto txn = env.txn_ro();

        std::vector<MsgWriter> writerMsgs;

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgIngester::ClientMessage>(&newMsg.msg)) {
                try {
                    if (msg->payload.starts_with('[')) {
                        auto payload = tao::json::from_string(msg->payload);

                        if (cfg().relay__logging__dumpInAll) LI << "[" << msg->connId << "] dumpInAll: " << msg->payload; 

                        if (!payload.is_array()) throw herr("message is not an array");
                        auto &arr = payload.get_array();
                        if (arr.size() < 2) throw herr("bad message");

                        auto &cmd = arr[0].get_string();

                        if (cmd == "AUTH") {
                            if (arr.size() != 2) {
                                throw herr("invalid AUTH message format");
                            }

                            AuthMessage authMessage = ParseAuthMessage(arr[1]);

                            if(authMessage.kind != cfg().auth__msg__kind) {
                                throw herr("given AUTH message kind (" + std::to_string(authMessage.kind) + ") does not equal " + std::to_string(cfg().auth__msg__kind));
                            }
                            if(!isWithinLimit(authMessage.created_at, cfg().auth__msg__timestamp__tolerance)) {
                                throw herr("given AUTH message timestamp (" + std::to_string(authMessage.created_at) + ") is not within " + std::to_string(cfg().auth__msg__timestamp__tolerance) + " minutes of current time");
                            }

                            //Parse tags, anything other than challenge string and relay URL is ignored.
                            std::string challengeString;
                            std::string unresolvedRelayURL;
                            for (const auto &tag : authMessage.tags) {
                                if(tag[0] == cfg().auth__msg__challenge__tag) {
                                    if(!challengeString.empty()) {
                                        throw herr("Only one challenge string tag allowed");
                                    }
                                    challengeString = tag[1];
                                }
                                else if(tag[0] == cfg().auth__msg__relay__tag) {
                                    if(!unresolvedRelayURL.empty()) {
                                        throw herr("Only one relay URL tag allowed");
                                    }
                                    unresolvedRelayURL = tag[1];
                                }
                            }
                            if(challengeString.empty()) {
                                throw herr("Missing challenge string");
                            }
                            if(unresolvedRelayURL.empty()) {
                                throw herr("Missing relay URL");
                            }
                            std::cout << "Challenge String " << challengeString << "\n";
                            relayURL resolvedRelayURL = ParseRelayURL(unresolvedRelayURL);
                            std::cout << "The IP address of " << unresolvedRelayURL << " is " << resolvedRelayURL.url << " on port " << resolvedRelayURL.port << "\n";

                            if(!isPubKeyAuth(authMessage.pubkey)) {
                                throw herr("Blocked: pubkey is not allowed to publish to this relay");
                            }

                            std::string sigBin = hex2bin(authMessage.sig);
                            std::string idBin = hex2bin(authMessage.id);
                            std::string pubkeyBin = hex2bin(authMessage.pubkey);                    

                            if (!verifySig(secpCtx, sigBin, idBin, pubkeyBin)) {
                                setAuthState(msg->connId, false);
                                sendNoticeError(msg->connId, "authentication failed: invalid signature");
                                //closeConnection(connId); //TODO do we want to close connection if client is not authenticated or something else?
                            }
                            else {
                                if(!doChallengeStringsMatch(msg->connId, challengeString)) {
                                    setAuthState(msg->connId, false);
                                    sendNoticeError(msg->connId, "authentication failed: challenge strings do not match");
                                }
                                else if(resolvedRelayURL.url != cfg().relay__bind || resolvedRelayURL.port != cfg().relay__port) {
                                    setAuthState(msg->connId, false);
                                    sendNoticeError(msg->connId, "authentication failed: Relay URL and or port do not match");
                                }
                                else {
                                    std::cout << "verifySig successful" << "\n";                           
                                    setAuthState(msg->connId, true);
                                    sendOKResponse(msg->connId, "AUTH", true, "authentication successful");
                                }
                            } 
                        } else if (cmd == "EVENT") {
                            if (cfg().relay__logging__dumpInEvents) LI << "[" << msg->connId << "] dumpInEvent: " << msg->payload; 

                            try {
                                ingesterProcessEvent(txn, msg->connId, msg->ipAddr, secpCtx, arr[1], writerMsgs);
                            } catch (std::exception &e) {
                                sendOKResponse(msg->connId, arr[1].at("id").get_string(), false, std::string("invalid: ") + e.what());
                                if (cfg().relay__logging__invalidEvents) LI << "Rejected invalid event: " << e.what();
                            }
                        } else if (cmd == "REQ") {
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInReq: " << msg->payload; 

                            try {
                                ingesterProcessReq(txn, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("bad req: ") + e.what());
                            }
                        } else if (cmd == "CLOSE") {
                            if (cfg().relay__logging__dumpInReqs) LI << "[" << msg->connId << "] dumpInReq: " << msg->payload; 

                            try {
                                ingesterProcessClose(txn, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("bad close: ") + e.what());
                            }
                        } else if (cmd.starts_with("NEG-")) {
                            try {
                                ingesterProcessNegentropy(txn, decomp, msg->connId, arr);
                            } catch (std::exception &e) {
                                sendNoticeError(msg->connId, std::string("negentropy error: ") + e.what());
                            }
                        } else {
                            throw herr("unknown cmd");
                        }
                    } else if (msg->payload == "\n") {
                        // Do nothing.
                        // This is for when someone is just sending newlines on websocat for debugging purposes.
                    } else {
                        throw herr("unparseable message");
                    }
                } catch (std::exception &e) {
                    sendNoticeError(msg->connId, std::string("bad msg: ") + e.what());
                }
            } else if (auto msg = std::get_if<MsgIngester::CloseConn>(&newMsg.msg)) {
                auto connId = msg->connId;
                tpWriter.dispatch(connId, MsgWriter{MsgWriter::CloseConn{connId}});
                tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::CloseConn{connId}});
                tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::CloseConn{connId}});
            }
        }

        if (writerMsgs.size()) {
            tpWriter.dispatchMulti(0, writerMsgs);
        }
    }
}

void RelayServer::ingesterProcessEvent(lmdb::txn &txn, uint64_t connId, std::string ipAddr, secp256k1_context *secpCtx, const tao::json::value &origJson, std::vector<MsgWriter> &output) {
    std::string flatStr, jsonStr;

    parseAndVerifyEvent(origJson, secpCtx, true, true, flatStr, jsonStr);

    auto *flat = flatbuffers::GetRoot<NostrIndex::Event>(flatStr.data());

    {
        auto existing = lookupEventById(txn, sv(flat->id()));
        if (existing) {
            LI << "Duplicate event, skipping";
            sendOKResponse(connId, to_hex(sv(flat->id())), true, "duplicate: have this event");
            return;
        }
    }

    output.emplace_back(MsgWriter{MsgWriter::AddEvent{connId, std::move(ipAddr), hoytech::curr_time_us(), std::move(flatStr), std::move(jsonStr)}});
}

void RelayServer::ingesterProcessReq(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr) {
    if (arr.get_array().size() < 2 + 1) throw herr("arr too small");
    if (arr.get_array().size() > 2 + 20) throw herr("arr too big");

    Subscription sub(connId, arr[1].get_string(), NostrFilterGroup(arr));

    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::NewSub{std::move(sub)}});
}

void RelayServer::ingesterProcessClose(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr) {
    if (arr.get_array().size() != 2) throw herr("arr too small/big");

    tpReqWorker.dispatch(connId, MsgReqWorker{MsgReqWorker::RemoveSub{connId, SubId(arr[1].get_string())}});
}

void RelayServer::ingesterProcessNegentropy(lmdb::txn &txn, Decompressor &decomp, uint64_t connId, const tao::json::value &arr) {
    if (arr.at(0) == "NEG-OPEN") {
        if (arr.get_array().size() < 5) throw herr("negentropy query missing elements");

        NostrFilterGroup filter;
        auto maxFilterLimit = cfg().relay__negentropy__maxSyncEvents + 1;

        if (arr.at(2).is_string()) {
            auto ev = lookupEventById(txn, from_hex(arr.at(2).get_string()));
            if (!ev) {
                sendToConn(connId, tao::json::to_string(tao::json::value::array({
                    "NEG-ERR",
                    arr[1].get_string(),
                    "FILTER_NOT_FOUND"
                })));

                return;
            }

            tao::json::value json = tao::json::from_string(getEventJson(txn, decomp, ev->primaryKeyId));

            try {
                filter = std::move(NostrFilterGroup::unwrapped(tao::json::from_string(json.at("content").get_string()), maxFilterLimit));
            } catch (std::exception &e) {
                sendToConn(connId, tao::json::to_string(tao::json::value::array({
                    "NEG-ERR",
                    arr[1].get_string(),
                    "FILTER_INVALID"
                })));

                return;
            }
        } else {
            filter = std::move(NostrFilterGroup::unwrapped(arr.at(2), maxFilterLimit));
        }

        Subscription sub(connId, arr[1].get_string(), std::move(filter));

        uint64_t idSize = arr.at(3).get_unsigned();
        if (idSize < 8 || idSize > 32) throw herr("idSize out of range");

        std::string negPayload = from_hex(arr.at(4).get_string());

        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegOpen{std::move(sub), idSize, std::move(negPayload)}});
    } else if (arr.at(0) == "NEG-MSG") {
        std::string negPayload = from_hex(arr.at(2).get_string());
        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegMsg{connId, SubId(arr[1].get_string()), std::move(negPayload)}});
    } else if (arr.at(0) == "NEG-CLOSE") {
        tpNegentropy.dispatch(connId, MsgNegentropy{MsgNegentropy::NegClose{connId, SubId(arr[1].get_string())}});
    } else {
        throw herr("unknown command");
    }
}
