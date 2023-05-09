#pragma once

#include <iostream>
#include <memory>
#include <algorithm>

#include <hoytech/time.h>
#include <hoytech/hex.h>
#include <hoytech/file_change_monitor.h>
#include <uWebSockets/src/uWS.h>
#include <tao/json.hpp>
#include <quadrable.h>

#include "golpe.h"

#include "Subscription.h"
#include "ThreadPool.h"
#include "events.h"
#include "filters.h"
#include "yesstr.h"




struct MsgWebsocket : NonCopyable {
    struct Send {
        uint64_t connId;
        std::string payload;
    };

    struct SendBinary {
        uint64_t connId;
        std::string payload;
    };

    struct SendEventToBatch {
        RecipientList list;
        std::string evJson;
    };

    using Var = std::variant<Send, SendBinary, SendEventToBatch>;
    Var msg;
    MsgWebsocket(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgIngester : NonCopyable {
    struct ClientMessage {
        uint64_t connId;
        std::string ipAddr;
        std::string payload;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<ClientMessage, CloseConn>;
    Var msg;
    MsgIngester(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgWriter : NonCopyable {
    struct AddEvent {
        uint64_t connId;
        std::string ipAddr;
        uint64_t receivedAt;
        std::string flatStr;
        std::string jsonStr;
    };

    using Var = std::variant<AddEvent>;
    Var msg;
    MsgWriter(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgReqWorker : NonCopyable {
    struct NewSub {
        Subscription sub;
    };

    struct RemoveSub {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<NewSub, RemoveSub, CloseConn>;
    Var msg;
    MsgReqWorker(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgReqMonitor : NonCopyable {
    struct NewSub {
        Subscription sub;
    };

    struct RemoveSub {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    struct DBChange {
    };

    using Var = std::variant<NewSub, RemoveSub, CloseConn, DBChange>;
    Var msg;
    MsgReqMonitor(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgYesstr : NonCopyable {
    struct SyncRequest {
        uint64_t connId;
        std::string yesstrMessage;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<SyncRequest, CloseConn>;
    Var msg;
    MsgYesstr(Var &&msg_) : msg(std::move(msg_)) {}
};

struct RelayServer {
    std::unique_ptr<uS::Async> hubTrigger;
    std::unordered_map<uint64_t, bool> authStates; //NIP-42
    flat_hash_map<uint64_t, std::string> challengeStrings; //NIP-42
    // Thread Pools

    ThreadPool<MsgWebsocket> tpWebsocket;
    ThreadPool<MsgIngester> tpIngester;
    ThreadPool<MsgWriter> tpWriter;
    ThreadPool<MsgReqWorker> tpReqWorker;
    ThreadPool<MsgReqMonitor> tpReqMonitor;
    ThreadPool<MsgYesstr> tpYesstr;
    std::thread cronThread;

    void run();

    void runWebsocket(ThreadPool<MsgWebsocket>::Thread &thr);

    void runIngester(ThreadPool<MsgIngester>::Thread &thr);
    void ingesterProcessEvent(lmdb::txn &txn, uint64_t connId, std::string ipAddr, secp256k1_context *secpCtx, const tao::json::value &origJson, std::vector<MsgWriter> &output);
    void ingesterProcessReq(lmdb::txn &txn, uint64_t connId, const tao::json::value &origJson);
    void ingesterProcessClose(lmdb::txn &txn, uint64_t connId, const tao::json::value &origJson);

    void runWriter(ThreadPool<MsgWriter>::Thread &thr);

    void runReqWorker(ThreadPool<MsgReqWorker>::Thread &thr);

    void runReqMonitor(ThreadPool<MsgReqMonitor>::Thread &thr);

    void runYesstr(ThreadPool<MsgYesstr>::Thread &thr);

    void runCron();

    // Utils (can be called by any thread)

    void sendToConn(uint64_t connId, std::string &&payload) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(payload)}});
        hubTrigger->send();
    }

    void sendToConnBinary(uint64_t connId, std::string &&payload) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::SendBinary{connId, std::move(payload)}});
        hubTrigger->send();
    }

    void sendEvent(uint64_t connId, const SubId &subId, std::string_view evJson) {
        auto subIdSv = subId.sv();

        std::string reply;
        reply.reserve(13 + subIdSv.size() + evJson.size());

        reply += "[\"EVENT\",\"";
        reply += subIdSv;
        reply += "\",";
        reply += evJson;
        reply += "]";

        sendToConn(connId, std::move(reply));
    }

    void sendEventToBatch(RecipientList &&list, std::string &&evJson) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::SendEventToBatch{std::move(list), std::move(evJson)}});
        hubTrigger->send();
    }

    void sendNoticeError(uint64_t connId, std::string &&payload) {
        LI << "sending error to [" << connId << "]: " << payload;
        auto reply = tao::json::value::array({ "NOTICE", std::string("ERROR: ") + payload });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendOKResponse(uint64_t connId, std::string_view eventIdHex, bool written, std::string_view message) {
        auto reply = tao::json::value::array({ "OK", eventIdHex, written, message });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void setAuthState(uint64_t connId, bool isAuthenticated) {
        auto it = authStates.find(connId);
        if (it != authStates.end()) {
            it->second = isAuthenticated;
        } else {
            authStates.emplace(connId, isAuthenticated);
        }
    }

    bool isClientAuthenticated(secp256k1_context *secpCtx, const std::string signedChallenge, const std::string &challengeHash, const std::string &client_pub_key);
};

inline bool RelayServer::isClientAuthenticated(secp256k1_context *secpCtx, const std::string signedChallenge, const std::string &challengeHash, const std::string &client_pub_key) {

    // Use the verifySig method from events.cpp
    return verifySig(secpCtx, signedChallenge, challengeHash, client_pub_key);
}
