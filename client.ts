import * as msgpack from "msgpack5";
import * as fs from "fs";
import { createHash } from "crypto";
import bignum = require("bignum");
import struct = require("python-struct");

function sign_seq(seq: Uint8Array) : Uint8Array
{
    return createHash("sha256").update(seq).digest();
}

function merge_signs(base: Uint8Array, add: Uint8Array) : Uint8Array
{
    if (base.length != add.length || base.length != 32)
    {
        throw new Error("not sha256 signature/hash");
    }

    const res = new Uint8Array(32);
    for (let i = 0; i < 32; ++i)
    {
        res[i] = base[i] ^ add[i];
    }
    return createHash("sha256").update(res).digest();
}

const seq = (+new Date()).toString();

const b = new bignum(seq);

const cap = fs.readFileSync("/home/fatih/woof1.cap");

const sig = cap.slice(cap.length - 32);

const seq_hash = sign_seq(b.toBuffer({
    endian: "little",
    size: 8
}));

const x = new Date();
const body = msgpack().encode([1, "test", "fwd4_fun", 5, 10, 
                                struct.pack("<QQQQQQ", 1, 2, 3, 
                                    (x.getTime() + x.getTimezoneOffset()*60*1000), 5, 6)]);

const req_hash = sign_seq(body.slice(0));

const merged_sign = merge_signs(merge_signs(sig, seq_hash), req_hash);

console.error("signature: " + sig.toString("hex"));
console.error("seq sig: " + new Buffer(seq_hash).toString("hex"));
console.error("merged signature: " + new Buffer(merged_sign).toString("hex"));
Object.assign(sig, merged_sign);
console.error("signature: " + sig.toString("hex"));

const req = msgpack().encode([cap, body, parseInt(seq)]);

console.log(req.toString("hex"));
