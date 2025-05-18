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
const SelectiveAck = mcs_proto.SelectiveAck;
const DataMessageStanza = mcs_proto.DataMessageStanza;

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
    this.#socket.on("connect", this.#handleSocketConnect);
    this.#socket.on("close", (hadError: boolean) =>
      this.#handleSocketClose(hadError),
    );
    this.#socket.on("error", this.#handleSocketError);

    this.#parser = new Parser(this.#socket);
    this.#parser.emmiter.on("message", this.#handleMessage);
    this.#parser.emmiter.on("error", this.#handleParserError);

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

    const persistentId =
      object.persistentId && typeof object.persistentId === "string"
        ? object.persistentId
        : undefined;
    const lastStreamIdReceived =
      object.lastStreamIdReceived &&
      typeof object.lastStreamIdReceived === "number"
        ? object.lastStreamIdReceived
        : undefined;

    if (lastStreamIdReceived) {
      // TODO(TheLeoP): remove all outgoing/incoming messages from the
      // outgoing/incoming queue(database?) with id smaller that
      // `lastStreamIdReceived` (currently there is no such implementation)
    }

    // TODO(TheLeoP): send IqStanzaTag message if necessary
    // https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gcm/engine/mcs_client.cc;l=681;drc=662daa264bb05fe250ce6102be8038dc722182e4

    switch (tag) {
      case MCSProtoTag.kLoginResponseTag:
        // clear persistent ids, as we just sent them to the server while logging in
        this.#config.persistentIds.length = 0;
        this.emmiter.emit("ON_READY");
        this.#startHeartbeat();
        this.#ready.resolve();
        break;

      case MCSProtoTag.kDataMessageStanzaTag:
        this.#handleDataMessage(
          object as unknown as mcs_proto.IDataMessageStanza,
        );
        break;

      case MCSProtoTag.kHeartbeatPingTag:
        this.emmiter.emit("ON_HEARTBEAT");
        debug("HEARTBEAT PING", object);
        this.#sendHeartbeatPong(object as unknown as mcs_proto.IHeartbeatAck);
        break;

      case MCSProtoTag.kHeartbeatAckTag:
        this.emmiter.emit("ON_HEARTBEAT");
        debug("HEARTBEAT PONG", object);
        break;

      case MCSProtoTag.kCloseTag:
        debug("Close: Server requested close! message: ", object);
        this.#handleSocketClose();
        break;

      case MCSProtoTag.kLoginRequestTag:
        debug("Login request: message: ", object);
        break;

      case MCSProtoTag.kIqStanzaTag:
        debug("IqStanza: ", object);
        const stanza = object as unknown as mcs_proto.IIqStanza;
        const extension = stanza.extension;
        if (!extension) return debug("Received invalid iq stanza extension");

        const selectiveAck = 12;
        const streamAck = 13;
        switch (extension.id) {
          case selectiveAck: {
            // TODO(TheLeoP): this is throwing an error, only read if not empty?
            // const selectiveAck = SelectiveAck.decodeDelimited(extension.data);

            // TODO(TheLeoP):
            // https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gcm/engine/mcs_client.cc;l=821;drc=662daa264bb05fe250ce6102be8038dc722182e4

            break;
          }
          case streamAck: {
            // TODO(TheLeoP): the following comment is copied verbatim from the
            // chromium code-base. Does it apply to us?

            // Do nothing. The last received stream id is always processed if it's
            // present.
            break;
          }
          default: {
            debug("Received invalid iq stanza extension");
            break;
          }
        }
        break;

      default:
        error("Unknown message: ", object);
        return;

      // no default
    }

    this.#streamId++;
  };

  #handleDataMessage = (object: mcs_proto.IDataMessageStanza): void => {
    if (!this.#config.credentials) throw new Error("credentials is undefined");
    if (!object.appData)
      throw new Error("incoming message does not have appData");

    if (
      !object.persistentId ||
      this.persistentIds.includes(object.persistentId)
    )
      return;

    debug("handleDataMessage");
    debug(object);

    // The category of messages intended for the GCM client itself from MCS.
    const MCS_CATEGORY = "com.google.android.gsf.gtalkservice";
    if (object.category === MCS_CATEGORY) {
      // TODO(TheLeoP): does this actually work? Is it needed? This is implemented on the chromium code

      const kIdleNotification = "IdleNotification";
      if (!!object.appData.find((item) => item.key === kIdleNotification)) {
        const response: mcs_proto.IDataMessageStanza = {
          // The from field for messages originating in the GCM client.
          from: "gcm@android.com",
          category: MCS_CATEGORY,
          sent: Long.fromString(Date.now().toString()), // TODO(TheLeoP): now timestamp. What format?
          ttl: 0,
          appData: [
            {
              key: kIdleNotification,
              value: "false",
            },
          ],
        };
        const err = DataMessageStanza.verify(response);
        if (err) throw new Error(err);
        const buffer = DataMessageStanza.encodeDelimited(response).finish();

        if (!this.#socket) throw new Error("socket is nil");
        this.#socket.write(
          Buffer.concat([
            Buffer.from([MCSProtoTag.kDataMessageStanzaTag]),
            buffer,
          ]),
        );
      }

      return;
    }

    const isEncrypted =
      !!object.appData.find((item) => item.key === "encryption") &&
      !!object.appData.find((item) => item.key === "crypto-key") &&
      object.rawData &&
      object.rawData.length > 0;
    if (isEncrypted) {
      let message: Types.Message;
      try {
        message = decrypt<Types.Message>(object, this.#config.credentials.keys);
      } catch (error) {
        if (!(error instanceof Error)) return;

        switch (true) {
          case error.message.includes(
            "Unsupported state or unable to authenticate data",
          ):
          case error.message.includes("crypto-key is missing"):
          case error.message.includes("salt is missing"):
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
      return;
    }

    // TODO(TheLeoP): for some reason, push messages contain neither of this types, so it should be unknown
    const messageType = (object.appData.find(
      (item) => item.key === "message_type",
    )?.value ?? "unknown") as
      | "delete_message"
      | "send_error"
      | "gcm"
      | "unknown"
      | undefined;
    // TODO(TheLeoP): it looks like this needs to be done before trying to
    // decrypt the message and only if the messageType is gcm, but gcm
    // messages do not contain a message_type header. Why? Does it maybe have
    // to do with the advertised version?
    debug("messageType", messageType);

    switch (messageType) {
      case "delete_message": {
        // TODO(TheLeoP): notify someone? the chromium codebase seems not to do anything
        // meaningful in this case (?
        break;
      }
      case "send_error": {
        // TODO(TheLeoP): notify someone? the chromium codebase seems not to do anything
        // meaningful in this case (?
        break;
      }
    }
  };

  #handleParserError = (err: Error) => {
    error(err);
    this.#socketRetry();
  };
}

export { PushReceiver };
