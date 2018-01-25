import * as express from "express"
import * as bodyParser from "body-parser"
import { authRouter, toSecond, AuthParam } from "../index"
import * as Cache from "node-cache"
import * as crypto from "crypto"
import * as scrypt from "scryptsy"
import * as logger from "winston"
import * as http from "http"
import * as expressWs from "express-ws"
import { Subject } from "rxjs/Subject"
import { Request } from "express"

logger.configure({
  level: 'debug',
  transports: [
    new logger.transports.Console({
      level: 'debug',
      timestamp: true
    })
  ]
})

export class App {
  express: express.Application
  cache = new Cache({ stdTTL: 60 })
  authCache = new Cache({ stdTTL: 60 })
  users = [
    {
      userhash: '',
      username: 'dev',
      name: 'Dev',
      roles: ['root', 'developer'],
      salt: '',
      password: 'dodol123'
    }
  ]
  roles = [
    { code: 'root', name: 'ROOT' },
    { code: 'dev', name: 'Developer' }
  ]

  config = {
    userSalt: "userhashsalt1",
    // [
    //   "userhashsalt1",
    // "userhashsalt2",
    // "userhashsalt3",
    // "userhashsalt4",
    // ],
    scrypt: { N: 8192, r: 8, p: 1 },
    secret: "thisisverysecurerandomtext",
    tokenExpiry: "15m",
    saltExpiry: "2m",
    refreshTokenExpiry: "12h"
  }

  constructor() {
    this.express = express()
    this.users.forEach(v => {
      if (typeof this.config.userSalt === 'string') {
        v.userhash = scrypt(v.username, this.config.userSalt, this.config.scrypt.N, this.config.scrypt.r, this.config.scrypt.p, 64).toString('base64')
      } else {
        (this.config.userSalt as any[]).forEach((us, i) => {
          v[`userhash${i != 0 ? i : ''}`] = scrypt(v.username, us, this.config.scrypt.N, this.config.scrypt.r, this.config.scrypt.p, 64).toString('base64')
        })
      }
      let salt = scrypt(v.userhash, crypto.randomBytes(64), 1, this.config.scrypt.r, this.config.scrypt.p, 64)
      v.salt = salt.toString('base64')
      v.password = scrypt(v.password, salt, this.config.scrypt.N, this.config.scrypt.r, this.config.scrypt.p, 64).toString('base64')
    })
    this.init()
  }

  init() {
    let param: AuthParam = {
      config: this.config,
      getAuth: (userhash): Promise<any> => {
        return Promise.resolve(this.authCache.get(userhash))
      },
      setAuth: (va): Promise<any> => {
        this.authCache.set(va.userhash, va, toSecond("1h"))
        return Promise.resolve(va)
      },
      removeAuth: (userhash): Promise<any> => {
        let va = this.authCache.get(userhash)
        this.authCache.del(userhash)
        return Promise.resolve(va)
      },
      getCache: (key): Promise<any> => {
        return Promise.resolve(this.cache.get(key))
      },
      setCache: (key, value, duration: number): Promise<any> => {
        this.cache.set(key, value, duration)
        return Promise.resolve(value)
      },
      removeCache: (key): Promise<any> => {
        let value = this.cache.get(key)
        this.cache.del(key)
        return Promise.resolve(value)
      },
      getUser: (userhash: String, saltIndex: number): Promise<any> => {
        return Promise.resolve(this.users.find((v): boolean => {
          return v[`userhash${saltIndex != 0 ? saltIndex : ''}`] === userhash
        }))
      },
      getRoles: (roles: String[]): Promise<any[]> => {
        return Promise.resolve(
          this.roles.filter((v): boolean => {
            return roles.indexOf(v.code) >= 0
          })
        )
      },
      validateNonce: (nonce: String): Promise<boolean> => {
        return Promise.resolve(true)
      },
      getSaltIndex: (req: Request): number => {
        if (typeof this.config.userSalt === 'string') return 0
        let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
        console.log('HEADERS ', req.headers)
        let hmac = crypto.createHmac("sha256", 'USER-SALT')
        hmac.update(ip.toString())
        if (req.headers['user-agent']) {
          hmac.update(req.headers['user-agent'].toString())
        }
        let xor = 0
        hmac.digest().forEach(v => xor ^= v)
        return xor % (this.config.userSalt as any[]).length
      }
    }
    authRouter.init(param)
    this.express.disable("x-powered-by")
    this.express.use(authRouter.validateAuthorization)
    this.express.use(bodyParser.json())
    this.express.use(bodyParser.urlencoded({ extended: false }))
    this.express.use('/auth', authRouter.router)
    this.express.use((err, req, res, next) => {
      logger.warn('Router error', err)
      if (err.status && err.name && err.message) {
        res.status(err.status).json({ name: err.name, message: err.message, detail: err.detail })
      } else {
        res.status(500).json(err)
      }
    })
  }
}

export const app = new App()
export const server = http.createServer(app.express)
server.listen(3789)
server.on("error", (error: NodeJS.ErrnoException) => {
  if (error.syscall !== "listen") throw error
  switch (error.code) {
    case "EACCES":
      logger.error(`port requires elevated privileges`)
      process.exit(1)
      break
    case "EADDRINUSE":
      logger.error(`port is already in use`)
      process.exit(1)
      break
    default:
      throw error
  }
})
server.on("listening", () => {
  console.log('LISTENING ', server.address())
  app.express.set("server.address", server.address())
})

expressWs(App)
