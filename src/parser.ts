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
  #messageTag = 0;
  #messageSize = 0;
  #handshakeComplete = false;
  #isWaitingForData = true;

  constructor(socket: TLSSocket) {
    this.#socket = socket;
    this.#socket.on("data", this.#handleData);
  }

  destroy(): void {
    this.#isWaitingForData = false;
    this.#socket.removeListener("data", this.#handleData);
  }

  #emitError(error: Error): void {
    this.destroy();
    this.emmiter.emit("error", error);
  }

  #handleData = (buffer: Buffer) => {
    debug(`Got data: ${buffer.length}`);
    this.#data = Buffer.concat([this.#data, buffer]);
    if (this.#isWaitingForData) {
      this.#isWaitingForData = false;
      this.#waitForData();
    }
  };

  #waitForData() {
    debug(`waitForData state: ${this.#state}`);

    let minBytesNeeded = 0;

    switch (this.#state) {
      case ProcessingState.MCS_VERSION_TAG_AND_SIZE:
        minBytesNeeded += Variables.kVersionPacketLen;
      // eslint-disable-next-line no-fallthrough
      case ProcessingState.MCS_TAG_AND_SIZE:
        minBytesNeeded += Variables.kTagPacketLen;
      // eslint-disable-next-line no-fallthrough
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

    if (this.#data.length < minBytesNeeded) {
      debug(
        `Waiting for ${minBytesNeeded - this.#data.length} more bytes. Got ${this.#data.length}`,
      );
      this.#isWaitingForData = true;
      return;
    }

    debug(`Processing MCS data: state == ${this.#state}`);

    switch (this.#state) {
      case ProcessingState.MCS_VERSION_TAG_AND_SIZE:
        this.#handleGotVersion();
        this.#handleGotMessageTag();
        this.#handleGotMessageSize();
        break;
      case ProcessingState.MCS_TAG_AND_SIZE:
        this.#handleGotMessageTag();
        this.#handleGotMessageSize();
        break;
      case ProcessingState.MCS_SIZE:
        this.#handleGotMessageSize();
        break;
      case ProcessingState.MCS_PROTO_BYTES:
        this.#handleGotMessageBytes();
        break;
      default:
        this.#emitError(new Error(`Unexpected state: ${this.#state}`));
        return;
    }
  }

  #handleGotVersion() {
    const version = this.#data.readInt8(0);
    this.#data = this.#data.subarray(1);
    debug(`VERSION IS ${version}`);

    if (version < Variables.kMCSVersion && version !== 38) {
      this.#emitError(new Error(`Got wrong version: ${version}`));
      return;
    }
  }

  #handleGotMessageTag() {
    this.#messageTag = this.#data.readInt8(0);
    this.#data = this.#data.subarray(1);
    debug(`RECEIVED PROTO OF TYPE ${this.#messageTag}`);
  }

  #handleGotMessageSize() {
    let incompleteSizePacket = false;
    const reader = new ProtobufJS.BufferReader(this.#data);

    try {
      this.#messageSize = reader.int32();
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith("index out of range:")
      ) {
        incompleteSizePacket = true;
      } else if (error instanceof Error) {
        this.#emitError(error);
        return;
      }
    }

    // TODO(ibash) in chromium code there is an extra check here of:
    // if prev_byte_count >= kSizePacketLenMax then something else went wrong
    // NOTE(ibash) I could only test this case by manually cutting the buffer
    // above to be mid-packet like: new ProtobufJS.BufferReader(this.#data.slice(0, 1))
    if (incompleteSizePacket) {
      this.#state = ProcessingState.MCS_SIZE;
      // TODO(TheLeoP): this can cause infinite recursion
      this.#waitForData();
      return;
    }

    this.#data = this.#data.subarray(reader.pos);

    debug(`Proto size: ${this.#messageSize}`);

    if (this.#messageSize > 0) {
      this.#state = ProcessingState.MCS_PROTO_BYTES;
      this.#waitForData();
    } else {
      this.#handleGotMessageBytes();
    }
  }

  #handleGotMessageBytes() {
    const protobuf = this.#buildProtobufFromTag(this.#messageTag);
    if (!protobuf) {
      this.#emitError(new Error("Unknown tag"));
      return;
    }

    // Messages with no content are valid just use the default protobuf for
    // that tag.
    if (this.#messageSize === 0) {
      this.emmiter.emit("message", { tag: this.#messageTag, object: {} });
      this.#getNextMessage();
      return;
    }

    if (this.#data.length < this.#messageSize) {
      // Continue reading data.
      debug(
        `Continuing data read. Buffer size is ${this.#data.length}, expecting ${this.#messageSize}`,
      );
      this.#state = ProcessingState.MCS_PROTO_BYTES;
      this.#waitForData();
      return;
    }

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
      if (this.#handshakeComplete) {
        error("Unexpected login response");
      } else {
        this.#handshakeComplete = true;
        debug("GCM Handshake complete.");
      }
    }

    this.#getNextMessage();
  }

  #getNextMessage() {
    this.#messageTag = 0;
    this.#messageSize = 0;
    this.#state = ProcessingState.MCS_TAG_AND_SIZE;
    this.#waitForData();
  }

  #buildProtobufFromTag(tag: number) {
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
