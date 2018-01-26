import * as path from "path"
import * as express from "express"
import * as compression from "compression"
import * as bodyParser from "body-parser"
import * as proxy from "express-http-proxy"
import * as jwt from "jsonwebtoken"
import * as Cache from "node-cache"
import * as crypto from "crypto"

import { config } from "./config"
import { Sequelize, IFindOptions } from "sequelize-typescript"

import * as errorHandler from "errorhandler"

import * as logger from "winston"
import * as expressWinston from "express-winston"
import { Request, Router, RequestHandler } from "express"
import { RedisClient, createClient as CreateRedisClient } from "redis"
import { Auth } from "./auth";
import { server } from "./index";

export class App {
  public express: express.Application
  private sequelize: Sequelize
  private redisClient: RedisClient
  private auth: Auth
  private cacheBlock = new Cache({ stdTTL: 10 })
  private cache = new Cache({ stdTTL: 60 })

  constructor() {
    this.express = express()
  }

  async start() {
    config.db.logging = (msg, obj) => {
      logger.debug(msg, {
        database: obj.database,
        type: obj.type,
      })
    }
    this.redisClient = CreateRedisClient(config.redis)

    this.sequelize = new Sequelize(config.db)
    await this.sequelize.authenticate()
    Object.getOwnPropertyNames(config.models).forEach(async k => {
      let v = config.models[k]
      await this.sequelize.define(k, v.attributes, v.opts).sync({})
    })

    this.auth = new Auth(this.sequelize, this.redisClient)

    this.express.disable("x-powered-by")
    this.express.use(compression())
    if (process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test") {
      this.express.use(expressWinston.logger({
        winstonInstance: logger,
        level: "debug",
        expressFormat: true
      }))
    }
    this.express.use(this.auth.validateAuthorization)
    this.express.use(bodyParser.json())
    this.express.use(bodyParser.urlencoded({ extended: false }))
    this.express.use("/api/", this.auth.router)
    if (process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test") {
      this.express.use((err, req, res, next) => {
        logger.warn('Router error', err)
        if (err.status) {
          res.status(err.status).json(err)
        } else {
          res.status(500).json(err)
        }
      })
    } else {
      this.express.use((err, req, res, next) => {
        logger.warn('Router error', err)
        if (err.status && err.name && err.message) {
          res.status(err.status).json({ name: err.name, message: err.message })
        } else {
          res.status(500).json(err)
        }
      })
    }
    this.express.use(errorHandler())
    logger.info("Application running", { server: { address: this.express.get('server.address') } })
  }
}

export const app = new App()