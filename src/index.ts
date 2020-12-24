require('dotenv').config();

import {Connection, createConnection} from 'mysql2';

import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import Server from 'socket.io';
import { exit } from 'process';
import { IAuthToken } from './models/IAuthToken';

const mysqlcs = process.env.MYSQL_CONNECTION_STRING;
const schema: "prod" | "dev" = process.env.MYSQL_SCHEMA === "prod" ? "prod" : "dev";
const authTokenValidInterval = process.env.MYSQL_AUTH_TOKEN_VALID_INTERVAL ? process.env.MYSQL_AUTH_TOKEN_VALID_INTERVAL : "3 MONTH"

const io = new Server();

let dbConn: Connection;

try {
    dbConn = createConnection(mysqlcs!);
} catch (error) {
    console.error("There was no connection string specified for the sql server");
    exit(-1);
}

const app = express();
const port = process.env.PORT ? process.env.PORT : 6001;

app.use(bodyParser.json())
app.use((req, res, next)=>{
    res.setHeader('Access-Control-Allow-Origin', '*');

    next();
})

const addAuthToken = async (token: String) => {
    let query = `INSERT INTO ${schema}.authTokens (authToken, timeStamp) VALUES('${token}', NOW())`
    dbConn.query(query)
}

app.get("/", (req, res) => {
    res.send("Auth MicroService API is running")
})

app.post("/authenticateClient", async (req, res) => {
    // check validity of app requesting to authenticate client
    // for now assume that client is who they say they are until you build the full-fledged authenticator app

    let clientID = req.param("code")

    let newAuthToken = crypto.randomBytes(64).toString('hex')
    await addAuthToken(newAuthToken)

    io.to(clientID).emit("authenticateSession", newAuthToken)
    res.send(`authenticated client with code ${clientID}`)
})

app.get("/check", (req, res) => {
    let query = `
        SELECT *, (timeStamp > DATE_SUB(NOW(), INTERVAL ${authTokenValidInterval})) as isActive 
        FROM ${schema}.authTokens 
        WHERE authToken = '${req.param("token")}'`
    dbConn.query(query, (error, result: IAuthToken []) => {
        if (error) {
            res.send(`error: ${error.message}`)
        } else {
            if (result.length === 1 && result[0].isActive) {
                res.send(result[0])
            } else  {
                res.send(`error: auth token has expired`)
            }
        }
    })
})

app.listen(port, () => console.log(`Authentication microservice listening on port: ${port}!`));
io.attach(6004);
console.log("Authentication socket is open on port: 6004!");