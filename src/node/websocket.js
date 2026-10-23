// The smallest WebSocket server the relay needs (RFC 6455): the handshake,
// text frames out, and enough of the read side to answer ping and close. A
// watcher only listens, so any data frame from a client closes the socket.

import { createHash } from "node:crypto";

const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PING_MILLISECONDS = 25_000;

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
    raw.setNoDelay(true);
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

  send(text) {
    if (this.closed) throw new Error("closed");
    this.write(0x1, Buffer.from(String(text), "utf8"));
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
      const opcode = this.buffer[0] & 0x0f;
      const masked = (this.buffer[1] & 0x80) !== 0;
      let length = this.buffer[1] & 0x7f;
      // A client must mask; a watcher never needs a long frame.
      if (!masked || length > 125) return this.close(1002, "protocol error");
      if (this.buffer.length < 6 + length) return;
      const mask = this.buffer.subarray(2, 6);
      const payload = Buffer.from(this.buffer.subarray(6, 6 + length));
      for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
      this.buffer = this.buffer.subarray(6 + length);
      if (opcode === 0x8) {
        const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
        return this.close(code === 1005 || code === 1006 ? 1000 : code, "closed");
      }
      if (opcode === 0x9) {
        this.write(0xa, payload);
      } else if (opcode !== 0xa) {
        this.onmessage?.(payload);
      }
    }
  }
}
