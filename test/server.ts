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


  constructor() {
    this.express = express()
    this.users.forEach(v => {
      v.userhash = scrypt(v.username, 'userhashsalt', 16384, 8, 1, 64).toString('base64')
      let salt = scrypt(v.userhash, crypto.randomBytes(64), 1, 8, 1, 64)
      v.salt = salt.toString('base64')
      v.password = scrypt(v.password, salt, 16384, 8, 1, 64).toString('base64')
    })
    this.init()
  }

  init() {
    let param: AuthParam = {
      config: {
        scrypt: { N: 16384, r: 8, p: 1 },
        secret: "thisisverysecurerandomtext",
        tokenExpiry: "3s",
        saltExpiry: "2m",
        refreshTokenExpiry: "12h"
      },
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
      getUser: (userhash: String): Promise<any> => {
        return Promise.resolve(this.users.find((v): boolean => {
          return v.userhash === userhash
        }))
      },
      getRoles: (roles: String[]): Promise<any[]> => {
        return Promise.resolve(
          this.roles.filter((v): boolean => {
            return roles.indexOf(v.code) >= 0
          })
        )
      },
      validateRequestSequence: (seq: String): Promise<boolean> => {
        return Promise.resolve(true)
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
server.listen(3000)
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
