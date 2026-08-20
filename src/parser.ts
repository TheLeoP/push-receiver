import ProtobufJS from "protobufjs";
import { debug, error } from "./utils/logger.js";
import { TLSSocket } from "tls";
import * as Protos from "./protos.js";
import { Variables, ProcessingState, MCSProtoTag } from "./constants.js";

import { TypedEventEmitter } from "./emitter.js";

import type { DataPacket } from "./types.js";

// Parser parses wire data from gcm.
// This takes the role of WaitForData in the chromium connection handler.
//
// The main differences from the chromium implementation are:
// - Did not use a max packet length (kDefaultDataPacketLimit), instead we just
//   buffer data in this.#data
// - Error handling around protobufs
// - Setting timeouts while waiting for data
//
// ref: https://cs.chromium.org/chromium/src/google_apis/gcm/engine/connection_handler_impl.cc?rcl=dc7c41bc0ee5fee0ed269495dde6b8c40df43e40&l=178

interface ParserEvents {
  error: [Error];
  message: [DataPacket];
}

export default class Parser {
  emmiter = new TypedEventEmitter<ParserEvents>();

  #socket: TLSSocket;
  #state: ProcessingState = ProcessingState.MCS_VERSION_TAG_AND_SIZE;
  #data: Buffer = Buffer.alloc(0);
  #messageTag: MCSProtoTag = 0;
  #messageSize = 0;
  #isHandshakeCompleted = false;

  constructor(socket: TLSSocket) {
    this.#socket = socket;
    this.#socket.on("data", this.#handleData);
  }

  destroy(): void {
    this.#socket.removeListener("data", this.#handleData);
  }

  #emitError(error: Error): void {
    this.destroy();
    this.emmiter.emit("error", error);
  }

  #handleData = (buffer: Buffer) => {
    debug(`Got data: ${buffer.length}`);
    this.#data = Buffer.concat([this.#data, buffer]);

    this.#waitForData();
  };

  #waitForData() {
    // TODO: this shouldn't cause an infinite loop because the function will
    // return as soon as `this.#data.length < minBytesNeeded` and every
    // handleGot function makes `this.#data.length` smaller, right?
    while (true) {
      debug(`waitForData state: ${this.#state}`);

      let minBytesNeeded = 0;

      switch (this.#state) {
        case ProcessingState.MCS_VERSION_TAG_AND_SIZE:
          minBytesNeeded += Variables.kVersionPacketLen;
          minBytesNeeded += Variables.kTagPacketLen;
          minBytesNeeded += Variables.kSizePacketLenMin;
          break;
        case ProcessingState.MCS_TAG_AND_SIZE:
          minBytesNeeded += Variables.kTagPacketLen;
          minBytesNeeded += Variables.kSizePacketLenMin;
          break;
        case ProcessingState.MCS_SIZE:
          minBytesNeeded += Variables.kSizePacketLenMin;
          break;
        case ProcessingState.MCS_PROTO_BYTES:
          minBytesNeeded = this.#messageSize;
          break;
        default:
          this.#emitError(new Error(`Unexpected state: ${this.#state}`));
          return;
      }

      if (this.#data.length < minBytesNeeded)
        return debug(
          `Waiting for ${minBytesNeeded - this.#data.length} more bytes. Got ${this.#data.length}`,
        );

      debug(`Processing MCS data: state == ${this.#state}`);

      switch (this.#state) {
        case ProcessingState.MCS_VERSION_TAG_AND_SIZE: {
          let ok = this.#handleGotVersion();
          if (!ok) return;
          this.#handleGotMessageTag();
          ok = this.#handleGotMessageSize();
          if (!ok) return;
          break;
        }
        case ProcessingState.MCS_TAG_AND_SIZE: {
          this.#handleGotMessageTag();
          const ok = this.#handleGotMessageSize();
          if (!ok) return;
          break;
        }
        case ProcessingState.MCS_SIZE: {
          const ok = this.#handleGotMessageSize();
          if (!ok) return;
          break;
        }
        case ProcessingState.MCS_PROTO_BYTES: {
          const ok = this.#handleGotMessageBytes();
          if (!ok) return;
          break;
        }
        default:
          this.#emitError(new Error(`Unexpected state: ${this.#state}`));
          return;
      }
    }
  }

  #handleGotVersion() {
    const version = this.#data.readInt8(0);
    this.#data = this.#data.subarray(1);
    debug(`VERSION IS ${version}`);

    if (version < Variables.kMCSVersion && version !== 38) {
      this.#emitError(new Error(`Got wrong version: ${version}`));
      return false;
    }

    return true;
  }

  #handleGotMessageTag() {
    this.#messageTag = this.#data.readInt8(0);
    this.#data = this.#data.subarray(1);
    debug(`RECEIVED PROTO OF TYPE ${this.#messageTag}`);
  }

  #handleGotMessageSize() {
    const reader = new ProtobufJS.BufferReader(this.#data);

    try {
      this.#messageSize = reader.int32();
    } catch (error) {
      // TODO: there used to be a check here for a try-catch with
      // `error.message.startsWith("index out of range:")` to try and read the
      // package again if the package was incomplete. Since the code is
      // synchronous, there will never be more data to complete the packet and
      // the function would have returned early anyway if there wasn't enough
      // bytes to read a size packet. But, if there's some weird issue in the
      // future, it chould be a consequence of removing it
      if (error instanceof Error) {
        this.#emitError(error);
        return false;
      }
    }

    this.#data = this.#data.subarray(reader.pos);

    debug(`Proto size: ${this.#messageSize}`);

    // TODO: there used to be a check if this.#messageSize > 0 here. If true,
    // #waitForData was called, if false, handleGotMessageBytes was called
    // directly. I think both are equivalent, but if I find some weird erorr,
    // it could be this change
    this.#state = ProcessingState.MCS_PROTO_BYTES;
    return true;
  }

  #handleGotMessageBytes() {
    const protobuf = this.#buildProtobufFromTag(this.#messageTag);
    if (!protobuf) {
      this.#emitError(new Error("Unknown tag"));
      return true;
    }

    // Messages with no content are valid just use the default protobuf for
    // that tag.
    if (this.#messageSize === 0) {
      this.emmiter.emit("message", { tag: this.#messageTag, object: {} });

      this.#messageTag = 0;
      this.#messageSize = 0;
      this.#state = ProcessingState.MCS_TAG_AND_SIZE;
      return true;
    }

    // TODO: there used to be a check for `this.#data.length < this.#messageSize`
    // in here. I think it shouldn't be possible because of the early return if
    // there are not enough bytes, so I removed it. If there are any weird
    // issues in the future, they may be comming from here

    const buffer = this.#data.subarray(0, this.#messageSize);
    const message = protobuf.decode(buffer);

    this.#data = this.#data.subarray(this.#messageSize);

    const object = protobuf.toObject(message, {
      longs: String,
      enums: String,
      bytes: Buffer,
    });

    this.emmiter.emit("message", { tag: this.#messageTag, object });

    if (this.#messageTag === MCSProtoTag.kLoginResponseTag) {
      if (this.#isHandshakeCompleted) {
        error("Unexpected login response");
      } else {
        this.#isHandshakeCompleted = true;
        debug("GCM Handshake complete.");
      }
    }

    this.#messageTag = 0;
    this.#messageSize = 0;
    this.#state = ProcessingState.MCS_TAG_AND_SIZE;
    return true;
  }

  #buildProtobufFromTag(tag: MCSProtoTag) {
    switch (tag) {
      case MCSProtoTag.kHeartbeatPingTag:
        return Protos.mcs_proto.HeartbeatPing;
      case MCSProtoTag.kHeartbeatAckTag:
        return Protos.mcs_proto.HeartbeatAck;
      case MCSProtoTag.kLoginRequestTag:
        return Protos.mcs_proto.LoginRequest;
      case MCSProtoTag.kLoginResponseTag:
        return Protos.mcs_proto.LoginResponse;
      case MCSProtoTag.kCloseTag:
        return Protos.mcs_proto.Close;
      case MCSProtoTag.kIqStanzaTag:
        return Protos.mcs_proto.IqStanza;
      case MCSProtoTag.kDataMessageStanzaTag:
        return Protos.mcs_proto.DataMessageStanza;
      case MCSProtoTag.kStreamErrorStanzaTag:
        return Protos.mcs_proto.StreamErrorStanza;
      default:
        return null;
    }
  }
}
