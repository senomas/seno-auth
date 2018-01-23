import { app, server } from "./server"

import * as mocha from "mocha";
import * as chai from "chai";
import * as crypto from "crypto"
import * as scrypt from "scryptsy"
import * as jwt from "jsonwebtoken"
import { Subject } from "rxjs/Subject";

chai.use(require('chai-http'));
const expect = chai.expect;

let http = chai.request("http://localhost:3000");

const delay = async (ms) => {
  return new Promise((resolve, reject) => {
    setTimeout(() => resolve(), ms);
  })
}

function proofOfWork(...params): String {
  let t0 = Date.now()
  let id = 0
  while (true) {
    let nonce = id.toString(10)
    let hmac = crypto.createHmac("sha256", nonce)
    params.forEach(p => {
      hmac.update(p)
    })
    let dig = hmac.digest('hex')
    if (dig.slice(-3) === '000') {
      console.log('CALCULATING PROOF-OF-WORK DONE!', Date.now() - t0, nonce)
      return nonce
    } else {
      id++
    }
  }
}

server.on("listening", () => {
  http = chai.request(`http://localhost:${server.address().port}`);
})

describe("auth", function () {
  this.timeout(60000);
  let token: any;

  let username = 'dev';
  let password = 'dodol123'
  let userhash = scrypt(username, "userhashsalt", 16384, 8, 1, 64)

  after((done) => {
    server.close()
    done()
  })

  it("login", async () => {
    let ecdh = crypto.createECDH('secp256k1')
    ecdh.generateKeys()

    let authInitReq: any = {
      iat: Math.floor(Date.now() / 1000),
      eckey: ecdh.getPublicKey('base64'),
      userhash: userhash.toString('base64'),
    }
    authInitReq.nonce = proofOfWork(String(authInitReq.iat), ecdh.getPublicKey(), userhash)

    let authInit = (await http.post(`/auth`).send(authInitReq)).body;
    console.log("\n\nauthInit: ", authInit);
    let salt = jwt.decode(authInit.salt)
    console.log("\n\nsalt: ", salt);

    let passkey = scrypt(password, Buffer.from(salt.salt, 'base64'), 16384, 8, 1, 64).toString('base64')
    let passkey2 = scrypt(passkey, authInit.salt, 16384, 8, 1, 64).toString('base64')

    let secretkey = ecdh.computeSecret(Buffer.from(salt.eckey, 'base64'))

    let authData: any = {
      salt: authInit.salt,
      sk: salt.sk,
      eckey: ecdh.getPublicKey('base64'),
      userhash: userhash.toString('base64'),
      passkey2: passkey2
    }
    authData.nonce = proofOfWork(authInit.salt, ecdh.getPublicKey(), passkey2)
    console.log("\n\nauthData: ", JSON.stringify(authData, undefined, 2))

    let seq = 0

    let login = (await http.post(`/auth/login`).send(authData)).body;
    console.log("\n\nlogin: ", JSON.stringify(login, undefined, 2))

    let hmac = crypto.createHmac('sha256', secretkey)
    hmac.update(String(++seq))
    hmac.update(`/user`)
    let sig = hmac.digest('base64')

    let user = (await http.get(`/auth/user`).set('Authorization', `Bearer ${login.token}.${seq}.${sig}`)).body;
    console.log("\n\nuser: ", user);

    secretkey
  })

})