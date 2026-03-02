const crypto = require("crypto")

const MOD = 1n << 256n
const IV = Buffer.alloc(16,0)

function bufToBig(b) {
  if (b.length === 0) return 0n;
  return BigInt("0x" + b.toString("hex"))
}

function bigToBuf(x) {
  return Buffer.from(x.toString(16).padStart(64,"0"), "hex")
}

class CipherState {
  constructor(key) {
    this.key = key
  }

  reseed(msg) {
    const h = bufToBig(crypto.createHash("sha256").update(msg).digest()) % MOD
    
    const m = bufToBig(msg) % MOD
    const m2 = (m * m) % MOD
    const m3 = (m2 * m) % MOD
    const m4 = (m3 * m) % MOD
    const extra = (m4 + 3n*m3 + 3n*m2 + 7n*m) % MOD
    
    this.key = (this.key + h + extra) % MOD
    console.log(`Reseeded with message: ${msg.toString()} (h: ${h}, m: ${m}, extra: ${extra})`)
    console.log(`New key: ${this.key}`)
  }

  encrypt(pt) {
    const cipher = crypto.createCipheriv(
      "aes-256-ctr",
      bigToBuf(this.key),
      IV
    )
    return Buffer.concat([cipher.update(pt), cipher.final()])
  }
}

module.exports = {
  CipherState,
  bufToBig,
  bigToBuf
}