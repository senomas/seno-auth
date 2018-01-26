import * as fs from "fs"
import * as path from "path"
import * as yaml from "js-yaml"
import { DataType } from "sequelize-typescript";

let cfg: any = yaml.safeLoad(fs.readFileSync(path.join(__dirname, 'config.yaml'), 'utf8'))

Object.getOwnPropertyNames(cfg.models).forEach(k => {
  let v = cfg.models[k]
  Object.getOwnPropertyNames(v.attributes).forEach(pk => {
    let pv = v.attributes[pk]
    if (typeof pv === "string") {
      v.attributes[pk] = DataType[pv]
    } else {
      v.attributes[pk].type = DataType[v.attributes[pk].type]
    }
  })
})

export const config = cfg
