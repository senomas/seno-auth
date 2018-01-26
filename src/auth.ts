import { Router, RequestHandler, Request } from "express"
import * as crypto from "crypto"
import * as scrypt from "scryptsy"
import * as jwt from "jsonwebtoken"
import * as querystring from "querystring"
import * as logger from "winston"
import * as  NodeCache from "node-cache"
import { config } from "./config"
import { Sequelize } from "sequelize-typescript"
import { RedisClient } from "redis"
import { hook as authHook } from "./index";

interface AuthData {
  userhash: string,
  eckey?: string,
  key?: string,
  token?: string
}

export class Auth {
  private authCache = new NodeCache({ stdTTL: 60 })

  constructor(private sequelize: Sequelize, private redisClient: RedisClient) {
  }

  get router(): Router {
    let router = Router()

    router.get('', hook(this.getUsernameSalt))
    router.post('', hook(this.getLoginSalt))
    router.post('/login', hook(this.login))
    router.get('/user', hook(this.getLoginUser))
    router.get('/:token/refresh/:refreshToken', hook(this.refreshToken))
    router.delete('/:token', hook(this.logout))

    return router;
  }

  private getSalt = (create: boolean = true, key: string = null): { key, value } => {
    if (!key) {
      key = String(Math.floor(Date.now() / 900000))
    }
    return { key: key, value: 'dodol' }
  }

  private getAuth = (userhash: string): Promise<AuthData> => {
    return new Promise((resolve, reject) => {
      this.redisClient.get('auth:token:' + userhash, (err, v) => {
        if (err) {
          reject(err)
        } else if (v) {
          resolve(JSON.parse(v))
        } else {
          resolve(null)
        }
      })
    })
  }

  private setAuth = (auth: AuthData): Promise<AuthData> => {
    return new Promise((resolve, reject) => {
      this.redisClient.setex('auth:token:' + auth.userhash, toSecond(config.auth.refreshTokenExpiry), JSON.stringify(auth), (err, v) => {
        if (err) {
          reject(err)
        } else {
          resolve(auth)
        }
      })
    })
  }

  private removeAuth = (userhash: string): Promise<any> => {
    return new Promise((resolve, reject) => {
      this.redisClient.del('auth:token:' + userhash, (err, v) => {
        if (err) {
          reject(err)
        } else {
          resolve(v)
        }
      })
    })
  }

  private getUser = (userhash: string): Promise<any> => {
    return new Promise<any>((resolve, reject) => {
      this.sequelize.model('user').findOne<any>({ where: { userhash: userhash } }).then(v => resolve(v)).catch(e => reject(e))
    })
  }

  private getRoles = (codes: string[]): Promise<any[]> => {
    return new Promise<any[]>((resolve, reject) => {
      this.sequelize.model('role').findAll<any>({ where: { code: codes } }).then(v => resolve(v)).catch(e => reject(e))
    })
  }

  private removeNonce = (userhash: string): Promise<boolean> => {
    return new Promise<boolean>((resolve, reject) => {
      this.redisClient.del(`auth:nonce:${userhash}`, (err, v) => {
        if (err) {
          reject({ name: "Fatal", message: "System error", detail: "Redis error", err: err })
        } else {
          resolve(true)
        }
      })
    })
  }

  private validateNonce = (userhash: string, seq: number): Promise<boolean> => {
    return new Promise<boolean>((resolve, reject) => {
      let key = `auth:nonce:${userhash}`
      let keys = `auth:nonce:${userhash}:${seq}`
      this.redisClient.setnx(keys, '', (err, v) => {
        if (err) {
          reject({ name: "Fatal", message: "System error", detail: "Redis error", err: err })
        } else if (v == 0) {
          reject({ status: 400, name: "InvalidRequest", message: "Invalid request", detail: `Sequence already used ${seq}` })
        } else {
          this.redisClient.get(key, (err, v) => {
            if (err) {
              reject({ name: "Fatal", message: "System error", detail: "Redis error", err: err })
            } else if (!v || parseInt(v) < seq) {
              this.redisClient.setex(key, toSecond(config.auth.refreshTokenExpiry), String(seq), (err, v) => {
                if (err) {
                  reject({ name: "Fatal", message: "System error", detail: "Redis error", err: err })
                } else {
                  resolve(true)
                }
              })
            } else {
              reject({ status: 400, name: "InvalidRequest", message: "Invalid request", detail: `Invalid sequence already used ${v} !< ${seq}` })
            }
          })
        }
      })
      this.redisClient.expire(keys, 5)
    })
  }

  getUsernameSalt = async (req, res, next) => {
    res.json({ salt: config.auth.userSalt, scrypt: config.auth.scrypt })
  }

  getLoginSalt = async (req, res, next) => {
    let userhash = req.body.userhash
    if (!userhash) throw { status: 401, name: 'AuthError', message: 'Invalid user password', detail: 'getLoginSalt: no user hash' }

    if (!req.body.nonce) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'getLoginSalt: no nonce' }
    let hmac = crypto.createHmac("sha256", req.body.nonce)
    hmac.update(String(req.body.iat))
    hmac.update(Buffer.from(req.body.eckey, 'base64'))
    hmac.update(Buffer.from(userhash, 'base64'))
    let dig = hmac.digest('hex')
    if (dig.slice(-3) !== '000') throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'getLoginSalt: invalid nonce' }

    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress

    let ecdh = crypto.createECDH('secp256k1')
    ecdh.generateKeys()

    let va = await this.getAuth(userhash)
    if (!va) {
      va = { userhash: userhash }
    }
    va.eckey = ecdh.getPrivateKey('base64')
    va.key = ecdh.computeSecret(Buffer.from(req.body.eckey, 'base64')).toString('base64')
    this.setAuth(va)

    let user = await this.getUser(userhash)
    if (!user) throw { status: 401, name: 'AuthError', message: 'Invalid user password', detail: 'getLoginSalt: Invalid user' }

    let loginSalt: any = { sub: userhash, cip: ip, salt: user.salt, eckey: ecdh.getPublicKey('base64') }
    let salt = (await this.getSalt())
    loginSalt.sk = salt.key

    res.json({
      salt: jwt.sign(loginSalt, salt.value, {
        expiresIn: "120s"
      }) as string
    })
  }

  login = async (req, res, next) => {
    if (!req.body.salt) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: no login salt' }
    let loginSalt = jwt.decode(req.body.salt)

    if (!req.body.eckey) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: no eckey' }
    if (!req.body.passkey2) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: no passkey2' }
    if (!req.body.nonce) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: no nonce' }
    let hmac = crypto.createHmac("sha256", req.body.nonce)
    hmac.update(req.body.salt)
    hmac.update(Buffer.from(req.body.eckey, 'base64'))
    hmac.update(req.body.passkey2)
    let dig = hmac.digest('hex')
    if (dig.slice(-3) !== '000') throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: invalid nonce' }

    let userhash = loginSalt.sub
    let cpasskey2 = req.body.passkey2

    let va = await this.getAuth(userhash)
    if (!va) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: `No auth ${userhash}` }

    let ecdh = crypto.createECDH('secp256k1')
    ecdh.setPrivateKey(Buffer.from(va.eckey, 'base64'))

    if (ecdh.getPublicKey('base64') !== loginSalt.eckey) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: invalid eckey' }

    let salt = await this.getSalt(false, loginSalt.sk)
    if (!salt) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: no salt' }
    try {
      loginSalt = jwt.verify(req.body.salt, salt.value)
    } catch (err) {
      throw { status: 403, name: 'TokenExpiredError', message: err.message, detail: 'login: salt jwt error' }
    }
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if (ip !== loginSalt.cip) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'login: invalid ip' }

    let user = await this.getUser(userhash)
    if (!user) throw { status: 401, name: 'AuthError', message: 'Invalid user password', detail: 'login: Invalid user' }

    let passkey2 = scrypt(user.password, req.body.salt, config.auth.scrypt.N, config.auth.scrypt.r, config.auth.scrypt.p, 64).toString('base64')

    let xaes = crypto.createDecipheriv('aes-256-ctr', Buffer.from(va.key, 'base64'), ecdh.getPublicKey().slice(0, 16))
    let opasskey2 = Buffer.concat([xaes.update(Buffer.from(req.body.passkey2, 'base64')), xaes.final()]).toString('base64')

    if (passkey2 != opasskey2) throw { status: 401, name: 'AuthError', message: 'Invalid user password', detail: `login: Invalid password '${passkey2}' != '${opasskey2}'` }

    let tokenData: any = {
      sub: userhash,
      sk: salt.key,
      cip: ip,
      user: {
        username: user.username,
        name: user.name
      },
      roles: user.roles
    }

    let token = jwt.sign(
      tokenData,
      salt.value,
      { expiresIn: config.auth.tokenExpiry }
    ) as string

    va.token = jwt.sign(
      { sub: userhash, sk: salt.key, cip: ip },
      salt.value,
      { expiresIn: config.auth.refreshTokenExpiry }
    ) as string

    this.setAuth(va)

    let aes = crypto.createCipheriv('aes-256-ctr', Buffer.from(va.key, 'base64'), ecdh.getPublicKey().slice(0, 16))
    let xuser = Buffer.concat([aes.update(Buffer.from(JSON.stringify(user))), aes.final()]).toString("base64")

    hmac = crypto.createHmac('sha256', Buffer.from(va.key, 'base64'))
    hmac.update(token)
    hmac.update(va.token)
    hmac.update(xuser)

    await this.removeNonce(userhash)

    res.json({ token: token, refreshToken: va.token, user: xuser, sig: hmac.digest('base64') })
  }

  getLoginUser = async (req, res, next) => {
    if (!res.locals.token) throw { status: 403, name: 'AuthError', message: 'Invalid request', detail: 'getLoginUser: no token' }
    let token = res.locals.token

    let va = await this.getAuth(token.sub)
    if (!va) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'getLoginUser: no va' }

    let user = await this.getUser(token.sub)
    if (!user) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'getLoginUser: no user' }
    res.json(user)
  }

  refreshToken = async (req, res, next) => {
    if (!req.params.token) throw { status: 403, name: 'AuthError', message: 'Invalid request', detail: 'refreshToken: no token' }
    let token = jwt.decode(req.params.token)
    let salt = await this.getSalt(false, token.sk)
    token = jwt.verify(req.params.token, salt.value, { ignoreExpiration: true })

    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    if (ip !== token.cip) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'refreshToken: invalid ip' }

    if (!req.params.refreshToken) throw { status: 403, name: 'AuthError', message: 'Invalid request', detail: 'refreshToken: no refreshToken' }
    let refreshToken = jwt.decode(req.params.refreshToken)
    salt = await this.getSalt(false, refreshToken.sk)
    try {
      refreshToken = jwt.verify(req.params.refreshToken, salt.value)
    } catch (err) {
      throw { status: 403, name: 'TokenExpiredError', message: err.message, detail: 'refreshToken: jwt error' }
    }

    if (token.sub !== refreshToken.sub) throw { status: 403, name: 'AuthError', message: 'Invalid request', detail: 'refreshToken: invalid refreshToken.sub' }
    if (ip !== refreshToken.cip) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'refreshToken: invalid refreshToken ip' }

    let va = await this.getAuth(token.sub)
    if (!va) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'refreshToken: no va' }
    let ecdh = crypto.createECDH('secp256k1')
    ecdh.setPrivateKey(Buffer.from(va.eckey, 'base64'))

    let user = await this.getUser(token.sub)
    if (!user) throw { status: 401, name: 'AuthError', message: 'Invalid user', detail: 'refreshToken: no user' }

    let tokenData: any = {
      sub: refreshToken.sub,
      sk: salt.key,
      cip: ip,
      user: {
        username: user.username,
        name: user.name
      },
      roles: user.roles
    }

    let newToken = jwt.sign(
      tokenData,
      salt.value,
      { expiresIn: config.auth.tokenExpiry }
    ) as string

    va.token = jwt.sign(
      { sub: token.sub, sk: salt.key, cip: ip },
      salt.value,
      { expiresIn: config.auth.refreshTokenExpiry }
    ) as string

    this.setAuth(va)

    let aes = crypto.createCipheriv('aes-256-ctr', Buffer.from(va.key, 'base64'), ecdh.getPublicKey().slice(0, 16))
    let xuser = Buffer.concat([aes.update(Buffer.from(JSON.stringify(user))), aes.final()]).toString("base64")

    let hmac = crypto.createHmac('sha256', Buffer.from(va.key, 'base64'))
    hmac.update(newToken)
    hmac.update(va.token)
    hmac.update(xuser)

    res.json({ token: newToken, refreshToken: va.token, user: xuser, sig: hmac.digest('base64') })
  }

  logout = async (req, res, next) => {
    if (!req.params.token) throw { status: 403, name: 'AuthError', message: 'Invalid request', detail: 'logout: no token' }
    let token = jwt.decode(req.params.token)
    let salt = await this.getSalt(false, token.sk)
    try {
      token = jwt.verify(req.params.token, salt.value)
    } catch (err) {
      throw { status: 403, name: 'TokenExpiredError', message: err.message, detail: 'logout: jwt error' }
    }

    let va = await this.removeAuth(token.sub)

    await this.removeNonce(token.sub)

    res.json({ token: token })
  }

  validateAuthorization = hook(async (req, res, next) => {
    if (req.headers.authorization) {
      let auth = req.headers.authorization as string
      if (!auth.startsWith("Bearer ")) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'validateAuthorization: no authorization' }
      let az = auth.slice(7).trim().split(".")
      let authKey = az[0] + "." + az[1] + "." + az[2]

      let token = jwt.decode(authKey)
      let salt = await this.getSalt(false, token.sk)
      if (!salt) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'validateAuthorization: invalid salt' }
      try {
        token = jwt.verify(authKey, salt.value)
      } catch (err) {
        throw { status: 403, name: 'TokenExpiredError', message: err.message, detail: 'validateAuthorization: jwt error' }
      }

      res.locals.token = token
      if (az.length > 4) {
        res.locals.requestSequence = az[3]
        res.locals.requestSignature = az[4]

        if (!(await this.validateNonce(token.sub, parseInt(az[3])))) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'validateAuthorization: invalid request sequence' }
      } else {
        throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'validateAuthorization: no request sequence' }
      }

      let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      if (ip !== token.cip) {
        throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'invalid ip' }
      }
      let ac: any = await this.authCache.get(token.sub)
      if (ac) {
        res.locals.permissions = ac.permissions
        res.locals.key = ac.key
      } else {
        let permissions = []
        let roles = await this.getRoles(token.roles)
        roles.forEach((v: any) => {
          if (v.code === 'root') {
            permissions.push('root')
          } else if (v.permissions) {
            for (let vk in v.permissions) {
              if (typeof v.permissions[vk] === 'boolean' && v.permissions[vk]) {
                permissions.push(vk)
              }
            }
          }
        })
        let va = await this.getAuth(token.sub)
        ac = { permissions: permissions, key: Buffer.from(va.key, 'base64') }
        this.authCache.set(token.sub, ac)
        res.locals.permissions = permissions
        res.locals.key = ac.key
      }
    } else {
      res.locals.permissions = []
    }
    return next()
  })
}

function toSecond(tokenExpiryS: string): number {
  let tx = tokenExpiryS.slice(-1)
  let tokenExpiry = parseInt(tokenExpiryS.slice(0, -1))
  if (tx === 's') {
    // ignore
  } else if (tx == 'm') {
    tokenExpiry *= 60
  } else if (tx == 'h') {
    tokenExpiry *= 3600
  } else if (tx == 'd') {
    tokenExpiry *= 86400
  } else {
    throw `Invalid tokenExpiry '${tokenExpiryS}'`
  }
  return tokenExpiry
}

const hook = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => next(e))
