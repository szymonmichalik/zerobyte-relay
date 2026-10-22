// The smallest WebSocket server the relay needs (RFC 6455): the handshake,
// text and binary frames both ways, ping and close. Watchers only listen;
// signal sockets send binary frames of at most 64 KiB. Fragmented messages are
// not needed by any client and are refused.

import { createHash } from "node:crypto";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PING_MILLISECONDS = 25_000;
/** The largest frame a client may send: a signal frame. */
export const MAX_CLIENT_FRAME = 65_536;

export function handshake(rawSocket, request, protocol) {
  const key = request.headers.get("Sec-WebSocket-Key") ?? "";
  if (request.headers.get("Sec-WebSocket-Version") !== "13" || !/^[A-Za-z0-9+/]{22}==$/.test(key)) {
    return null;
  }
  const accept = createHash("sha1").update(key + GUID).digest("base64");
  const lines = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Accept: ${accept}`,
  ];
  if (protocol) lines.push(`Sec-WebSocket-Protocol: ${protocol}`);
  rawSocket.write(lines.join("\r\n") + "\r\n\r\n");
  return new Socket(rawSocket);
}

function frame(opcode, payload) {
  const length = payload.length;
  let head;
  if (length < 126) {
    head = Buffer.from([0x80 | opcode, length]);
  } else if (length < 65_536) {
    head = Buffer.alloc(4);
    head[0] = 0x80 | opcode;
    head[1] = 126;
    head.writeUInt16BE(length, 2);
  } else {
    head = Buffer.alloc(10);
    head[0] = 0x80 | opcode;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(length), 2);
  }
  return Buffer.concat([head, payload]);
}

export class Socket {
  constructor(raw) {
    this.raw = raw;
    this.closed = false;
    this.buffer = Buffer.alloc(0);
    this.onmessage = null;
    this.onclose = null;
    /** When the client last sent the text "ping", answered with "pong". */
    this.lastPing = null;
    raw.setNoDelay?.(true);
    raw.on("data", (chunk) => this.read(chunk));
    raw.on("close", () => this.finish(1006));
    raw.on("error", () => this.finish(1006));
    this.timer = setInterval(() => this.write(0x9, Buffer.alloc(0)), PING_MILLISECONDS);
    this.timer.unref?.();
  }

  write(opcode, payload) {
    if (this.closed || this.raw.destroyed) return;
    this.raw.write(frame(opcode, payload));
  }

  /** A string goes as a text frame, bytes as a binary frame. */
  send(message) {
    if (this.closed) throw new Error("closed");
    if (typeof message === "string") this.write(0x1, Buffer.from(message, "utf8"));
    else this.write(0x2, Buffer.from(message.buffer ?? message, message.byteOffset ?? 0, message.byteLength));
  }

  close(code = 1000, reason = "") {
    if (this.closed) return;
    const payload = Buffer.alloc(2 + Buffer.byteLength(reason));
    payload.writeUInt16BE(code, 0);
    payload.write(reason, 2);
    this.write(0x8, payload);
    this.closed = true;
    clearInterval(this.timer);
    this.raw.end();
    this.onclose?.(code);
  }

  finish(code) {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.timer);
    this.raw.destroy();
    this.onclose?.(code);
  }

  read(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 2 && !this.closed) {
      const fin = (this.buffer[0] & 0x80) !== 0;
      const opcode = this.buffer[0] & 0x0f;
      const masked = (this.buffer[1] & 0x80) !== 0;
      let length = this.buffer[1] & 0x7f;
      let offset = 2;
      // A client must mask.
      if (!masked) return this.close(1002, "protocol error");
      if (!fin || opcode === 0x0) return this.close(1003, "fragmented");
      if (length === 126) {
        if (this.buffer.length < 4) return;
        length = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.length < 10) return;
        const long = this.buffer.readBigUInt64BE(2);
        if (long > BigInt(MAX_CLIENT_FRAME)) return this.close(1009, "too big");
        length = Number(long);
        offset = 10;
      }
      if (length > MAX_CLIENT_FRAME) return this.close(1009, "too big");
      if (opcode >= 0x8 && length > 125) return this.close(1002, "protocol error");
      if (this.buffer.length < offset + 4 + length) return;
      const mask = this.buffer.subarray(offset, offset + 4);
      const payload = Buffer.from(this.buffer.subarray(offset + 4, offset + 4 + length));
      for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
      this.buffer = this.buffer.subarray(offset + 4 + length);
      if (opcode === 0x8) {
        const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
        return this.close(code === 1005 || code === 1006 ? 1000 : code, "closed");
      }
      if (opcode === 0x9) {
        this.write(0xa, payload);
      } else if (opcode === 0x1) {
        const text = payload.toString("utf8");
        // Keep-alive, as the Workers runtime answers it without waking the object.
        if (text === "ping") {
          this.lastPing = Date.now();
          this.write(0x1, Buffer.from("pong"));
        } else {
          this.onmessage?.(text);
        }
      } else if (opcode === 0x2) {
        this.onmessage?.(new Uint8Array(payload));
      } else if (opcode !== 0xa) {
        return this.close(1002, "protocol error");
      }
    }
  }
}
