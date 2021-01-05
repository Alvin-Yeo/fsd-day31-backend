// load libraries
const express = require('express');
const morgan = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');

// environment configurations
require('dotenv').config();
const PORT =  parseInt(process.argv[2]) || parseInt(process.env.PORT) || 3000;
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'abcd1234';

// create mysql connection pool
const pool = mysql.createPool({
    host: process.env.MYSQL_HOST || 'localhost',
    port: parseInt(process.env.MYSQL_PORT) || 3306,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE || 'paf2020',
    connectionLimit: parseInt(process.env.MYSQL_CONNECTION_LIMIT) || 4,
    timezone: '+08:00'
});

// sql closure
const mkQuery = (sql, pool) => {
    return (async(args) => {
        const conn = await pool.getConnection();

        try {
            const [ result, _ ] = await conn.query(sql, args || []);
            return result;
        } catch(error) {
            console.error(`[ERROR] Unable to execute sql statement.`);
            console.error(`[ERROR] Message: ${error}`);
            throw error;
        } finally {
            conn.release();
        }
    });
};

// sql statement
const SQL_AUTHENTICATE_USER_INFO = 'SELECT user_id FROM user WHERE user_id = ? AND password = sha1(?)';

// sql function
const authenticateUserInDB = mkQuery(SQL_AUTHENTICATE_USER_INFO, pool);

// confiure passport with a strategry
passport.use(
    new LocalStrategy(
        {
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true
        },
        /*
        (req, user, password, done) => {
            // perform the authentication
            console.info(`[INFO] Authenticating username: ${user}, password: ${password} ...`);
            const authResult = (user == password);

            if(authResult) {
                done(null, 
                    // info about the user
                    { 
                        username: user, 
                        loginTime: (new Date()).toString(),
                        security: 2 
                    }
                );
                return;
            }

            done('Incorrect username and password', false);
        }
        */
        async(req, user, password, done) => {
            // perform the authentication
            console.info(`[INFO] Authenticating username: ${user}, password: ${password} ...`);

            const authResult = await authenticateUserInDB([ user, password ]);

            if(authResult.length > 0) {
                done(null, 
                    // info about the user
                    { 
                        username: user, 
                        loginTime: (new Date()).toString(),
                        security: 2 
                    }
                );
                return;
            }

            done('Incorrect username and password', false);
       }
    )
);

// custom auth middleware closure
const mkAuth = (passport) => {
    return (req, res, next) => {
        passport.authenticate('local', 
            (err, user, info) => {
                if(null != err) {
                    res.status(401);
                    res.type('application/json');
                    res.json({ error: err });
                    return;
                }
                if(!user) {
                    res.status(401);
                    res.type('application/json');
                    res.json({ error: 'Unauthorized' });
                    return;
                }
                req.user = user;
                next();
            }
        )(req, res, next);
    }
};

const localStrategyAuth = mkAuth(passport);

// create an instance of express
const app = express();

// log all requests with morgan
app.use(morgan('combined'));

// handle POST requests
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// initialize passport
app.use(passport.initialize());

app.post('/login', 
    /*
    passport.authenticate('local', { session: false }),
    */
    /*
    (req, res, next) => {
        passport.authenticate('local', 
            (err, user, info) => {
                if(null != err) {
                    res.status(401);
                    res.type('application/json');
                    res.json({ error: err });
                }
                next();
            }
        )(req, res, next);
    },
    */
    localStrategyAuth,
    (req, res) => {
        // do something
        console.info(`[INFO] User: `, req.user);

        // generate JWT token
        const ts = new Date().getTime() / 1000;
        const token = jwt.sign({
            sub: req.user.username,
            iss: 'myapp',
            iat: ts,
            nbf: ts + 30,
            exp: ts + 45,
            data: {
                loginTime: req.user.loginTime
            }
        }, TOKEN_SECRET);

        res.status(200);
        res.type('application/json');
        res.json({ 
            message: `Login at ${new Date()}`,
            token 
        });
    }
);

// Authorization: Bearer <token>
app.get('/protected/secret', 
    (req, res, next) => {
        // check if the request has Authorization header
        const auth = req.get('Authorization');
        if(null == auth) {
            res.status(403);
            res.type('application/json');
            res.json({ message: 'Forbidden.' });
            return;
        }

        // check type of authorization
        const terms = auth.split(' ');
        if(terms.length != 2 || terms[0] != 'Bearer') {
            res.status(403);
            res.type('application/json');
            res.json({ message: 'Unauthorized.' });
            return;
        }

        // verify token
        const token = terms[1];

        try {
            const verified = jwt.verify(token, TOKEN_SECRET);
            console.info(`[INFO] Verified token: `, verified);
            req.token = verified;
            next();
        } catch(error) {
            res.status(403);
            res.type('application/json');
            res.json({ message: 'Invalid token.', error });
            return;
        }

    },
    (req, res) => {
        res.status(200);
        res.type('application/json');
        res.json({ meaning_of_life: 42 });
    }
);

// start app
const startApp = async (app, pool) => {
    const conn = await pool.getConnection();

    try {
        // pinging database
        console.info(`[INFO] Pinging database...`);
        await conn.ping();

        console.info(`[INFO] Pinging database successfully.`);
        conn.release();

        app.listen(PORT, () => {
            console.info(`[INFO] Application started on PORT ${PORT} at ${new Date()}`);
        });
    } catch(error) {
        console.error(`[ERROR] Failed to start server.`);
        console.error(`[ERROR] Unable to ping database.`);
        console.error(`[ERROR] Message: ${error}`);
    }
}

startApp(app, pool);