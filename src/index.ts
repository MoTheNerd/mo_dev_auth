require('dotenv').config()

import { MongoError, MongoClient, Db, } from 'mongodb';

import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import moment from 'moment';

const mongocs = process.env.MONGO_CONNECTION_STRING;
const app = express();
const port = process.env.PORT ? process.env.PORT : 6001;
let db: Db;

app.use(bodyParser.json())


require('mongodb').connect(mongocs, (err: MongoError, result: MongoClient) => {
    if (err) {
        console.log(err)
        process.exit(1);
    } else {
        db = result.db('default')
    }
})

const addAuthToken = async (token: String) => {
    await db.collection('auth_tokens').insertOne({ token, expiry: moment.utc().add(1, "M").toDate() })
}


app.get("/", (req: express.Request, res: express.Response) => {
    res.send("Auth MicroService API is running")
})

app.post("/authenticateUsingToken", async (req, res) => {
    let result = (await db.collection('auth_tokens').find({ token: req.body.token }).toArray())[0]
    if (result) {
        if (moment.utc(result.expiry).isAfter(moment.utc())) {
            res.send({
                code: 200,
                data: {
                    token: result.token,
                    expiry: moment.utc(result.expiry).format('YYYY/MM/DD HH:mm:ss')
                }
            })
        } else {
            await db.collection('auth_tokens').deleteOne({ token: req.body.token })
            let newAuthToken = crypto.randomBytes(64).toString('hex')
            addAuthToken(newAuthToken)
            res.send({
                code: 200,
                data: {
                    token: newAuthToken,
                    expiry: moment.utc().add(1, "M").format('YYYY/MM/DD HH:mm:ss'),
                }
            })
        }
    } else {
        res.send({
            code: 301,
            message: "Token not valid, please login."
        })
    }
})

app.post("/authenticate", async (req, res) => {
    console.log("authenticating...");
    let hashed_password = (await db.collection('general').find({}).toArray())[0].hashed_password
    if (req.body.password !== undefined){
        let result = await bcrypt.compare(req.body.password, hashed_password)
        if (result) {
            console.log("authenticated!");
            let newAuthToken = crypto.randomBytes(64).toString('hex');
            addAuthToken(newAuthToken);
            res.send({
                token: newAuthToken
            })
        } else {
            console.log("authentication failed.");
            res.send({ code: 301, message: "I couldn't authorize you. You're not me." });
        };
    }else{
        res.send({code: 301, message: "no password sent, password must be sent in body"})
    }
});


app.listen(port, () => console.log(`Authentication microservice listening on port: ${port}!`));
