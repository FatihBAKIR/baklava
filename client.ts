import * as msgpack from "msgpack5";
import * as fs from "fs";
import { createHash } from "crypto";
import bignum = require("bignum");

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

function GeneratePutRequest(capability : Buffer, data : Uint8Array) : Buffer {
    const seq = (+new Date()).toString();
    const b = new bignum(seq);
    
    const sig = capability.slice(capability.length - 32);

    const seq_hash = sign_seq(b.toBuffer({
        endian: "little",
        size: 8
    }));

    const PutId = 1;

    const HostId = 5; // Only used for repair
    const HostSeq = 42; // Only used for repair

    const body = msgpack().encode(
        [1, "test", "fwd4_fun", HostId, HostSeq, data]);
        
    const req_hash = sign_seq(body.slice(0));

    const merged_sign = merge_signs(merge_signs(sig, seq_hash), req_hash);

    Object.assign(sig, merged_sign);
    const req = msgpack().encode([cap, body, parseInt(seq)]);
    return req.slice(0);
};

const cap = fs.readFileSync("woof1.cap");

const req = GeneratePutRequest(cap, new Uint8Array(4));

console.log(req.toString("hex"));
