import * as fs from "fs"
import * as logger from "winston";
import * as LoggerElasticsearch from "winston-elasticsearch"
import * as express from "express"
import * as compression from "compression"
import * as bodyParser from "body-parser"
import * as http from "http"
import * as expressWs from "express-ws"
import * as jwt from "jsonwebtoken"
import * as crypto from "crypto"
import { config } from "./config"
import { app, App } from "./app"
import { Request } from "express";
import { Subject } from "rxjs/Subject";

let loggerTransports = [
  new logger.transports.Console({
    level: process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test" ? 'debug' : 'info',
    timestamp: true
  })
]

if (config.elastic) {
  let param = Object.assign({}, config.elastic)
  param.transformer = (logData) => {
    const transformed: any = {};
    transformed['@timestamp'] = logData.timestamp ? logData.timestamp : new Date().toISOString();
    transformed.message = logData.message;
    transformed.severity = logData.level;
    transformed.fields = logData.meta;
    transformed.type = 'log'
    transformed.tags = ['auth', 'log']
    return transformed
  }
  loggerTransports.push(new LoggerElasticsearch(param))
}

logger.configure({
  level: 'debug',
  transports: loggerTransports
})

const port = normalizePort(process.env.PORT || 3000)
app.express.set("port", port)

export const appReady: Subject<number> = new Subject()

export const server = http.createServer(app.express)
app.start().then(() => {
  server.listen(port)
}).catch(err => {
  logger.error(`Failed to initialized`, err)
  process.exit(1)
})

server.on("error", (error: NodeJS.ErrnoException) => {
  if (error.syscall !== "listen") throw error
  let bind = typeof port === "string" ? "Pipe " + port : "Port " + port
  switch (error.code) {
    case "EACCES":
      logger.error(`${bind} requires elevated privileges`)
      process.exit(1)
      break
    case "EADDRINUSE":
      logger.error(`${bind} is already in use`)
      process.exit(1)
      break
    default:
      throw error
  }
})
server.on("listening", () => {
  app.express.set("server.address", server.address())
  logger.info(`Server listening at ${server.address().port}`)
  appReady.next(server.address().port)
})

expressWs(App)

function normalizePort(val: number | string): number | string | boolean {
  let port: number = typeof val === "string" ? parseInt(val, 10) : val
  if (isNaN(port)) return val
  else if (port >= 0) return port
  else return false
}

export const hook = fn => (req: Request, res, next) => {
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
            data: process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test" ? {
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

// export function setPassword(user: any, userSalt: string, password: string) {
//   let userhash = scrypt(user.username, Buffer.from(userSalt), 16384, 8, 1, 64)
//   user.userhash = userhash.toString('base64')
//   let salt = scrypt(userhash, crypto.randomBytes(64), 1, 8, 1, 64)
//   user.salt = salt.toString('base64')
//   user.password = scrypt(password, salt, 16384, 8, 1, 64).toString('base64')
//   return user
// }

