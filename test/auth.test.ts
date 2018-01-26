import * as mocha from "mocha";
import * as chai from "chai";
import * as crypto from "crypto"
import * as scrypt from "scryptsy"
import * as jwt from "jsonwebtoken"
import { Subject } from "rxjs/Subject";
import { server, appReady } from "../src/index";
import { App, app } from "../src/app";
import * as logger from "winston"

chai.use(require('chai-http'));
const expect = chai.expect;

let http: ChaiHttp.Agent = chai.request(`http://localhost:3000`)

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
      logger.debug('CALCULATING PROOF-OF-WORK DONE!', Date.now() - t0, nonce)
      return nonce
    } else {
      id++
    }
  }
}

describe("auth", function () {
  this.timeout(60000);
  let token: any;

  let username = 'dev';
  let password = 'dodol123'

  before((done) => {
    logger.debug("STARTING SERVER...")
    appReady.subscribe(port => {
      http = chai.request(`http://localhost:${port}`)
      logger.debug("DONE START...", port)
      done()
    })
  })

  after((done) => server.close(done))

  it("login", async () => {
    let ecdh = crypto.createECDH('secp256k1')
    ecdh.generateKeys()

    let init = (await http.get(`/api`)).body;
    logger.debug('init', init)

    let scp = init.scrypt

    let userhash = scrypt(username, init.salt, scp.N, scp.r, scp.p, 64)

    let authInitReq: any = {
      iat: Math.floor(Date.now() / 1000),
      eckey: ecdh.getPublicKey('base64'),
      userhash: userhash.toString('base64'),
    }
    authInitReq.nonce = proofOfWork(String(authInitReq.iat), ecdh.getPublicKey(), userhash)

    let authInit = (await http.post(`/api`).send(authInitReq)).body;
    logger.debug("authInit: ", authInit);
    let salt = jwt.decode(authInit.salt)
    logger.debug("salt: ", salt);

    let secretkey = ecdh.computeSecret(Buffer.from(salt.eckey, 'base64'))

    let passkey = scrypt(password, Buffer.from(salt.salt, 'base64'), scp.N, scp.r, scp.p, 64).toString('base64')
    let passkey2 = scrypt(passkey, authInit.salt, scp.N, scp.r, scp.p, 64)

    let aes = crypto.createCipheriv('aes-256-ctr', secretkey, Buffer.from(salt.eckey, 'base64').slice(0, 16))
    let xpasskey2 = Buffer.concat([aes.update(passkey2), aes.final()]).toString("base64")

    let authData: any = {
      salt: authInit.salt,
      sk: salt.sk,
      eckey: ecdh.getPublicKey('base64'),
      userhash: userhash.toString('base64'),
      passkey2: xpasskey2
    }
    authData.nonce = proofOfWork(authInit.salt, ecdh.getPublicKey(), xpasskey2)
    logger.debug("authData: ", JSON.stringify(authData, undefined, 2))

    let seq = 0

    let login = (await http.post(`/api/login`).send(authData)).body;
    logger.debug("login: ", JSON.stringify(login, undefined, 2))

    let hmac = crypto.createHmac('sha256', secretkey)
    hmac.update(String(++seq))
    hmac.update(`/user`)
    let sig = hmac.digest('base64')

    let user = (await http.get(`/api/user`).set('Authorization', `Bearer ${login.token}.${seq}.${sig}`)).body;
    logger.debug("user: ", user);

    secretkey
  })

})