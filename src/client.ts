import Long from "long";
import ProtobufJS from "protobufjs";
import tls, { type TLSSocket } from "tls";
import registerGCM, { checkIn } from "./gcm.js";
import registerFCM from "./fcm.js";
import createKeys from "./keys.js";
import Parser from "./parser.js";
import decrypt from "./utils/decrypt.js";
import { debug, error, setDebug, warn } from "./utils/logger.js";
import { mcs_proto } from "./protos.js";
import defer from "./utils/defer.js";

import { TypedEventEmitter } from "./emitter.js";

import { Variables, MCSProtoTag } from "./constants.js";

import type * as Types from "./types.js";

export { Types };

ProtobufJS.util.Long = Long;
ProtobufJS.configure();

const HeartbeatPing = mcs_proto.HeartbeatPing;
const HeartbeatAck = mcs_proto.HeartbeatAck;
const LoginRequest = mcs_proto.LoginRequest;

const HOST = "mtalk.google.com";
const PORT = 5228;
const MAX_RETRY_TIMEOUT = 15;

interface ClientEvents {
  ON_MESSAGE_RECEIVED: [Types.MessageEnvelope];
  ON_CREDENTIALS_CHANGE: [Types.EventChangeCredentials];
  ON_CONNECT: [];
  ON_DISCONNECT: [];
  ON_READY: [];
  ON_HEARTBEAT: [];
}

export default class PushReceiver {
  emmiter = new TypedEventEmitter<ClientEvents>();

  #config: Types.InternalClientConfig;
  #socket?: TLSSocket;
  #retryCount = 0;
  #retryTimeout?: NodeJS.Timeout;
  #parser?: Parser;
  #heartbeatTimer?: NodeJS.Timeout;
  #heartbeatTimeout?: NodeJS.Timeout;
  #streamId = 0;
  #lastStreamIdReported = -1;
  #ready = defer();

  persistentIds: Types.PersistentId[];

  get fcmToken() {
    return this.#config.credentials?.fcm?.token;
  }

  constructor(config: Types.ClientConfig) {
    this.setDebug(config.debug);
    debug("constructor", config);

    this.#config = {
      bundleId: "receiver.push.com",
      chromeId: "org.chromium.linux",
      chromeVersion: "94.0.4606.51",
      vapidKey: "",
      persistentIds: [],
      heartbeatIntervalMs: 5 * 60 * 1000, // 5 min
      ...config,
    };

    this.persistentIds = this.#config.persistentIds ?? [];
  }

  get whenReady() {
    return this.#ready.promise;
  }

  setDebug(enabled?: boolean) {
    setDebug(enabled);
  }

  onNotification(
    listener: (data: Types.MessageEnvelope) => void,
  ): Types.DisposeFunction {
    this.emmiter.on("ON_MESSAGE_RECEIVED", listener);
    return () => this.emmiter.off("ON_MESSAGE_RECEIVED", listener);
  }

  onCredentialsChanged(
    listener: (data: Types.EventChangeCredentials) => void,
  ): Types.DisposeFunction {
    this.emmiter.on("ON_CREDENTIALS_CHANGE", listener);
    return () => this.emmiter.off("ON_CREDENTIALS_CHANGE", listener);
  }

  onReady(listener: () => void): Types.DisposeFunction {
    this.emmiter.on("ON_READY", listener);
    return () => this.emmiter.off("ON_READY", listener);
  }

  connect = async (): Promise<void> => {
    if (this.#socket) return;

    await this.registerIfNeeded();

    debug("connect");

    this.#lastStreamIdReported = -1;

    this.#socket = tls.connect({ host: HOST, port: PORT, servername: HOST });
    this.#socket.setKeepAlive(true);
    this.#socket.on("connect", () => this.#handleSocketConnect());
    this.#socket.on("close", (hadError: boolean) =>
      this.#handleSocketClose(hadError),
    );
    this.#socket.on("error", (err) => this.#handleSocketError(err));

    this.#parser = new Parser(this.#socket);
    this.#parser.emmiter.on("message", (data) => this.#handleMessage(data));
    this.#parser.emmiter.on("error", (err) => this.#handleParserError(err));

    this.#sendLogin();

    return new Promise((res) => {
      const dispose = this.onReady(() => {
        dispose();
        res();
      });
    });
  };

  destroy = (hadError: boolean) => {
    this.#clearReady();

    clearTimeout(this.#retryTimeout);
    this.#clearHeartbeat();

    if (this.#socket) {
      this.#socket.removeAllListeners();
      if (!hadError) this.#socket.end();
      this.#socket.destroy();
      this.#socket = undefined;
    }

    if (this.#parser) {
      this.#parser.destroy();
      this.#parser = undefined;
    }
  };

  get #configMetaData() {
    return {
      bundleId: this.#config.bundleId,
      projectId: this.#config.firebase.projectId,
      vapidKey: this.#config.vapidKey,
    };
  }

  checkCredentials(credentials: Types.Credentials) {
    // Structure check
    if (!credentials.fcm || !credentials.gcm || !credentials.keys) return false;
    if (!credentials.fcm.installation) return false;
    if (!credentials.config) return false;

    // Config data
    if (
      JSON.stringify(credentials.config) !==
      JSON.stringify(this.#configMetaData)
    )
      return false;

    return true;
  }

  async registerIfNeeded(): Promise<Types.Credentials> {
    if (
      this.#config.credentials &&
      this.checkCredentials(this.#config.credentials)
    ) {
      await checkIn(this.#config);

      return this.#config.credentials;
    }

    const keys = await createKeys();
    const gcm = await registerGCM(this.#config);
    const fcm = await registerFCM(gcm, keys, this.#config);

    const credentials: Types.Credentials = {
      keys,
      gcm,
      fcm,
      config: this.#configMetaData,
    };

    this.emmiter.emit("ON_CREDENTIALS_CHANGE", {
      oldCredentials: this.#config.credentials,
      newCredentials: credentials,
    });

    this.#config.credentials = credentials;

    debug("got credentials", credentials);

    return this.#config.credentials;
  }

  #clearReady() {
    if (!this.#ready.isResolved) {
      this.#ready.reject(new Error("Client destroyed"));
    }

    this.#ready = defer();
  }

  #clearHeartbeat() {
    clearTimeout(this.#heartbeatTimer);
    this.#heartbeatTimer = undefined;

    clearTimeout(this.#heartbeatTimeout);
    this.#heartbeatTimeout = undefined;
  }

  #startHeartbeat() {
    this.#clearHeartbeat();

    if (!this.#config.heartbeatIntervalMs) return;

    this.#heartbeatTimer = setTimeout(
      () => this.#sendHeartbeatPing(),
      this.#config.heartbeatIntervalMs,
    );
    this.#heartbeatTimeout = setTimeout(
      () => this.#socketRetry(),
      this.#config.heartbeatIntervalMs * 2,
    );
  }

  #handleSocketConnect = (): void => {
    this.#retryCount = 0;
    this.emmiter.emit("ON_CONNECT");
    this.#startHeartbeat();
  };

  #handleSocketClose = (hadError = false): void => {
    this.emmiter.emit("ON_DISCONNECT");
    this.#clearHeartbeat();
    this.#socketRetry(hadError);
  };

  #handleSocketError = (err: Error): void => {
    error(err);
    // ignore, the close handler takes care of retry
  };

  #socketRetry(hadError = false) {
    this.destroy(hadError);
    const timeout = Math.min(++this.#retryCount, MAX_RETRY_TIMEOUT) * 1000;
    this.#retryTimeout = setTimeout(() => this.connect(), timeout);
  }

  #getStreamId(): number {
    this.#lastStreamIdReported = this.#streamId;
    return this.#streamId;
  }

  #newStreamIdAvailable(): boolean {
    return this.#lastStreamIdReported != this.#streamId;
  }

  #sendHeartbeatPing() {
    const heartbeatPingRequest: mcs_proto.IHeartbeatPing = {};

    if (this.#newStreamIdAvailable()) {
      heartbeatPingRequest.lastStreamIdReceived = this.#getStreamId();
    }

    debug("Heartbeat send pong", heartbeatPingRequest);

    const errorMessage = HeartbeatPing.verify(heartbeatPingRequest);

    if (errorMessage) {
      throw new Error(errorMessage);
    }

    const buffer = HeartbeatPing.encodeDelimited(heartbeatPingRequest).finish();

    debug("HEARTBEAT sending PING", heartbeatPingRequest);

    if (!this.#socket) throw new Error("socket is nil");
    this.#socket.write(
      Buffer.concat([Buffer.from([MCSProtoTag.kHeartbeatPingTag]), buffer]),
    );
  }

  #sendHeartbeatPong(object: mcs_proto.IHeartbeatAck) {
    const heartbeatAckRequest: mcs_proto.IHeartbeatAck = {};

    if (this.#newStreamIdAvailable()) {
      heartbeatAckRequest.lastStreamIdReceived = this.#getStreamId();
    }

    if (object?.status) {
      heartbeatAckRequest.status = object.status;
    }

    debug("Heartbeat send pong", heartbeatAckRequest);

    const errorMessage = HeartbeatAck.verify(heartbeatAckRequest);
    if (errorMessage) {
      throw new Error(errorMessage);
    }

    const buffer = HeartbeatAck.encodeDelimited(heartbeatAckRequest).finish();

    debug("HEARTBEAT sending PONG", heartbeatAckRequest);

    if (!this.#socket) throw new Error("this.#socket is undefined");

    this.#socket.write(
      Buffer.concat([Buffer.from([MCSProtoTag.kHeartbeatAckTag]), buffer]),
    );
  }

  #sendLogin() {
    if (!this.#config.credentials) throw new Error("credentials are undefined");

    const gcm = this.#config.credentials.gcm;
    const hexAndroidId = Long.fromString(gcm.androidId).toString(16);
    const loginRequest: mcs_proto.ILoginRequest = {
      adaptiveHeartbeat: false,
      authService: 2,
      authToken: gcm.securityToken,
      id: `chrome-${this.#config.chromeVersion}`,
      domain: "mcs.android.com",
      deviceId: `android-${hexAndroidId}`,
      networkType: 1,
      resource: gcm.androidId,
      user: gcm.androidId,
      useRmq2: true,
      setting: [{ name: "new_vc", value: "1" }],
      clientEvent: [],
      // Id of the last notification received
      receivedPersistentId: this.#config.persistentIds,
    };

    if (this.#config.heartbeatIntervalMs) {
      loginRequest.heartbeatStat = {
        ip: "",
        timeout: true,
        intervalMs: this.#config.heartbeatIntervalMs,
      };
    }

    const errorMessage = LoginRequest.verify(loginRequest);
    if (errorMessage) {
      throw new Error(errorMessage);
    }

    const buffer = LoginRequest.encodeDelimited(loginRequest).finish();

    if (!this.#socket) throw new Error("this.#socket is undefined");
    this.#socket.write(
      Buffer.concat([
        Buffer.from([Variables.kMCSVersion, MCSProtoTag.kLoginRequestTag]),
        buffer,
      ]),
    );
  }

  #handleMessage = ({ tag, object }: Types.DataPacket): void => {
    // any message will reset the client side heartbeat timeout.
    this.#startHeartbeat();

    switch (tag) {
      case MCSProtoTag.kLoginResponseTag:
        // clear persistent ids, as we just sent them to the server while logging in
        this.#config.persistentIds.length = 0;
        this.emmiter.emit("ON_READY");
        this.#startHeartbeat();
        this.#ready.resolve();
        break;

      case MCSProtoTag.kDataMessageStanzaTag:
        this.#handleDataMessage(object);
        break;

      case MCSProtoTag.kHeartbeatPingTag:
        this.emmiter.emit("ON_HEARTBEAT");
        debug("HEARTBEAT PING", object);
        this.#sendHeartbeatPong(object);
        break;

      case MCSProtoTag.kHeartbeatAckTag:
        this.emmiter.emit("ON_HEARTBEAT");
        debug("HEARTBEAT PONG", object);
        break;

      case MCSProtoTag.kCloseTag:
        debug(
          "Close: Server requested close! message: ",
          JSON.stringify(object),
        );
        this.#handleSocketClose();
        break;

      case MCSProtoTag.kLoginRequestTag:
        debug("Login request: message: ", JSON.stringify(object));
        break;

      case MCSProtoTag.kIqStanzaTag:
        debug("IqStanza: ", JSON.stringify(object));
        // FIXME: If anyone knows what is this and how to respond, please let me know
        break;

      default:
        error("Unknown message: ", JSON.stringify(object));
        return;

      // no default
    }

    this.#streamId++;
  };

  #handleDataMessage = (object: mcs_proto.IDataMessageStanza): void => {
    if (!this.#config.credentials) throw new Error("credentials is undefined");

    if (
      !object.persistentId ||
      this.persistentIds.includes(object.persistentId)
    ) {
      return;
    }

    let message;
    try {
      message = decrypt(object, this.#config.credentials.keys) as Types.Message;
    } catch (error) {
      if (!(error instanceof Error)) return;

      switch (true) {
        case error.message.includes(
          "Unsupported state or unable to authenticate data",
        ):
        case error.message.includes("crypto-key is missing"):
        case error.message.includes("salt is missing"):
          // NOTE(ibash) Periodically we're unable to decrypt notifications. In
          // all cases we've been able to receive future notifications using the
          // same keys. So, we silently drop this notification.
          warn(
            "Message dropped as it could not be decrypted: " + error.message,
          );
          return;
        default:
          throw error;
      }
    }

    // Maintain persistentIds updated with the very last received value
    this.persistentIds.push(object.persistentId);
    // Send notification
    this.emmiter.emit("ON_MESSAGE_RECEIVED", {
      message,
      // Needs to be saved by the client
      persistentId: object.persistentId,
    });
  };

  #handleParserError = (err: Error) => {
    error(err);
    this.#socketRetry();
  };
}

export { PushReceiver };
