import { Router, RequestHandler, Request } from "express"
import * as crypto from "crypto"
import * as scrypt from "scryptsy"
import * as jwt from "jsonwebtoken"
import * as querystring from "querystring"
import * as logger from "winston"

interface Auth {
  userhash,
  eckey?: string,
  key?: string,
  token?,
  attempts?: any[]
}

interface User {
  userhash,
  username?,
  name?,
  salt?,
  password?,
  roles?
}

interface Role {
  code,
  name
}

export interface AuthParam {
  config: any,
  getAuth: (id) => Promise<any>,
  setAuth?: (auth) => Promise<any>,
  removeAuth?: (userhash) => Promise<any>,
  getCache: (key) => Promise<any>,
  setCache: (key, value, duration: number) => Promise<any>,
  removeCache?: (key) => Promise<any>,
  getUser?: (userhash: String, saltIndex: number) => Promise<any>,
  getRoles: (roles: string[]) => Promise<any[]>,
  getSaltIndex?: (req: Request) => number
  validateNonce: (nonce: string) => Promise<boolean>
}

export class AuthRouter {

  private config: any

  private getAuth: (userhash) => Promise<Auth>

  private setAuth: (auth: Auth) => Promise<Auth>

  private removeAuth: (userhash) => Promise<Auth>

  private getCache: (key) => Promise<any>

  private setCache: (key, value, duration: number) => Promise<any>

  private removeCache: (key) => Promise<any>

  private getUser: (userhash: String, saltIndex: number) => Promise<User>

  private getRoles: (codes: String[]) => Promise<Role[]>

  private getSaltIndex: (req: Request) => number

  private validateNonce: (nonce: string) => Promise<boolean>

  private hook = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => next(e))

  get router(): Router {
    let router = Router()

    router.get('', this.hook(this.getUsernameSalt))
    router.post('', this.hook(this.getLoginSalt))
    router.post('/login', this.hook(this.login))
    router.get('/user', this.getLoginUser)
    router.get('/:token/refresh/:refreshToken', this.hook(this.refreshToken))
    router.delete('/:token', this.hook(this.logout))

    return router;
  }

  init(param: AuthParam) {
    this.config = param.config
    this.getAuth = param.getAuth
    this.setAuth = param.setAuth
    this.removeAuth = param.removeAuth
    this.getCache = param.getCache
    this.setCache = param.setCache
    this.removeCache = param.removeCache
    this.getUser = param.getUser
    this.getRoles = param.getRoles
    this.validateNonce = param.validateNonce
    this.getSaltIndex = param.getSaltIndex || ((req) => 0)
  }

  private getSalt = (create: boolean = true, key: string = null): { key, value } => {
    if (!key) {
      key = String(Math.floor(Date.now() / 900000))
    }
    return { key: key, value: 'dodol' }
  }

  getUsernameSalt = async (req, res, next) => {
    if (typeof this.config.userSalt === 'string') {
      res.json({ salt: this.config.userSalt, scrypt: this.config.scrypt })
    } else {
      res.json({ salt: this.config.userSalt[this.getSaltIndex(req)], scrypt: this.config.scrypt })
    }
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

    let user: User = await this.getUser(userhash, this.getSaltIndex(req))
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

    let user: User = await this.getUser(userhash, this.getSaltIndex(req))
    if (!user) throw { status: 401, name: 'AuthError', message: 'Invalid user password', detail: 'login: Invalid user' }

    let passkey2 = scrypt(user.password, req.body.salt, this.config.scrypt.N, this.config.scrypt.r, this.config.scrypt.p, 64).toString('base64')

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
      roles: user.roles.map(v => v.code)
    }

    let token = jwt.sign(
      tokenData,
      salt.value,
      { expiresIn: this.config.tokenExpiry }
    ) as string

    va.token = jwt.sign(
      { sub: userhash, sk: salt.key, cip: ip },
      salt.value,
      { expiresIn: this.config.refreshTokenExpiry }
    ) as string
    if (!va.attempts) va.attempts = [] as any
    va.attempts.push({ time: new Date(), saltKey: salt.key })
    if (va.attempts.length > 10) va.attempts = va.attempts.slice(-10)

    this.setAuth(va)

    let aes = crypto.createCipheriv('aes-256-ctr', Buffer.from(va.key, 'base64'), ecdh.getPublicKey().slice(0, 16))
    let xuser = Buffer.concat([aes.update(Buffer.from(JSON.stringify(user))), aes.final()]).toString("base64")

    hmac = crypto.createHmac('sha256', Buffer.from(va.key, 'base64'))
    hmac.update(token)
    hmac.update(va.token)
    hmac.update(xuser)

    res.json({ token: token, refreshToken: va.token, user: xuser, sig: hmac.digest('base64') })
  }

  getLoginUser = authHook(async (req, res, next) => {
    if (!res.locals.token) throw { status: 403, name: 'AuthError', message: 'Invalid request', detail: 'getLoginUser: no token' }
    let token = res.locals.token

    let va = await this.getAuth(token.sub)
    if (!va) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'getLoginUser: no va' }

    let user = await this.getUser(token.sub, this.getSaltIndex(req))
    if (!user) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'getLoginUser: no user' }
    res.json(user)
  })

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

    let user: User = await this.getUser(token.sub, this.getSaltIndex(req))
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
      { expiresIn: this.config.tokenExpiry }
    ) as string

    va.token = jwt.sign(
      { sub: token.sub, sk: salt.key, cip: ip },
      salt.value,
      { expiresIn: this.config.refreshTokenExpiry }
    ) as string
    if (!va.attempts) va.attempts = [] as any
    va.attempts.push({ time: new Date(), saltKey: salt.key })
    if (va.attempts.length > 10) va.attempts = va.attempts.slice(-10)

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

    res.json({ token: token })
  }

  validateAuthorization = this.hook(async (req, res, next) => {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let bip = await this.getCache('block:' + ip)
    if (bip) {
      if (bip === 't') {
        throw { status: 400, name: 'AuthError', message: 'IP blocked', detail: 'validateAuthorization: ip blocked' }
      }
    }

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

        if (!(await this.validateNonce(token.sub + '.' + az[3]))) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'validateAuthorization: invalid request sequence' }
      } else {
        throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'validateAuthorization: no request sequence' }
      }

      if (ip !== token.cip) {
        throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'invalid ip' }
      }
      let ac = await this.getCache('auth:' + token.sub)
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
        this.setCache('auth:' + token.sub, ac, 10)
        res.locals.permissions = permissions
        res.locals.key = ac.key
      }
    } else {
      res.locals.permissions = []
    }
    return next()
  })
}

const authHook = fn => (req: Request, res, next) => {
  try {
    if (req.headers.authorization) {
      if (res.locals.key) {
        if (!res.locals.requestSequence) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'no request sequence' }
        if (!res.locals.requestSignature) throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'no request signature' }

        let hmac = crypto.createHmac('sha256', res.locals.key)
        hmac.update(res.locals.requestSequence)
        hmac.update(req.url)
        if (req.body && (req.method === "PATCH" || req.method === "POST")) {
          hmac.update(JSON.stringify(req.body))
        }
        let sig = hmac.digest('base64')
        if (sig !== res.locals.requestSignature) {
          throw {
            status: 400, name: 'AuthError', message: 'Invalid request', detail: 'invalid signature',
            data: process.env.NODE_ENV === "development" ? {
              seq: res.locals.requestSequence,
              url: req.url,
              body: (req.body && (req.method === "PATCH" || req.method === "POST")) ? JSON.stringify(req.body) : undefined
            } : undefined
          }
        }
      } else {
        throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'no secret key' }
      }
    } else {
      throw { status: 400, name: 'AuthError', message: 'Invalid request', detail: 'no authorization' }
    }
    return Promise.resolve(fn(req, res, next)).catch(e => next(e))
  } catch (e) {
    next(e)
  }
}

export const hook = authHook

export function toSecond(tokenExpiryS: string): number {
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

export const authRouter = new AuthRouter()