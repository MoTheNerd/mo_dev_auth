const express = require('express');
const connectionString = require('../certs/mysql.json').connectionString;
const mysql = require('mysql').createConnection(connectionString);
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const app = express();
const port = 6001;
const moment = require('moment');

app.use(bodyParser.json())

mysql.connect()

const addAuthToken = async (token) => {
    await mysql.query(`SELECT * FROM modev_admin_tokens;`, (err, result) => {
        if (err) {
            mysql.query("CREATE TABLE modev_admin_tokens (TOKEN VARCHAR(255), EXPIRES DATETIME);")
        }
        mysql.query(`INSERT INTO modev_admin_tokens (TOKEN, EXPIRES) VALUES ('${token.toString('hex')}', '${moment().add(1, "M").format('YYYY/MM/DD HH:mm:ss')}');`)
        mysql.commit()
    })
}

app.post("/authenticateUsingToken", async (req, res) => {
    await mysql.query(`SELECT * FROM modev_admin_tokens WHERE TOKEN = '${req.body.token}';`, (err, result) => {
        if (err || result.length === 0) {
            res.send("token not valid, please login first")
        }else{
            if (moment(result[0]["EXPIRES"]).isAfter(moment())){
                res.send({
                    code: 200,
                    data: {
                        TOKEN: result[0]["TOKEN"],
                        EXPIRES: moment(result[0]["EXPIRES"]).format('YYYY/MM/DD HH:mm:ss')
                    }
                })
            }else{
                let newAuthToken = crypto.randomBytes(64)
                addAuthToken(newAuthToken)
                res.send({
                    code: 200,
                    data: {
                        TOKEN: newAuthToken.toString('hex'),
                        EXPIRES: moment().format('YYYY/MM/DD HH:mm:ss')
                    }
                })
            }
        }
    })
})

app.post("/authenticate", async (req, res) => {
    console.log("authenticating...");
    mysql.query(`SELECT * FROM modev_admin_pass;`, async (err, result) => {
        if (err) {
            mysql.connect();
            await mysql.query(`CREATE TABLE modev_admin_pass (HASHED_PASS VARCHAR(255));`);
            console.log("PASSWORD NOT MANUALLY SET.");
            res.send("PASSWORD NOT SET. PLEASE SET BEFORE AUTHENTICATING.");
        } else {
            await bcrypt.compare(req.body.password, result[0]["HASHED_PASS"], async (err, result) => {
                if (err) { res.send(err) } else if (result) {
                    console.log("authenticated!");
                    let newAuthToken = crypto.randomBytes(64);
                    addAuthToken(newAuthToken);
                    res.send({
                        token: newAuthToken.toString('hex')
                    })
                } else {
                    console.log("authentication failed.");
                    res.send({ code: 301, message: "I couldn't authorize you. You're not me." });
                };
            });
        };
    });
});


app.listen(port, () => console.log(`Authentication microservice listening on port: ${port}!`));
