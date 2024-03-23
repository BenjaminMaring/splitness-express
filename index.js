const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

// Allows us to access the .env
require('dotenv').config();

const app = express();
const port = process.env.PORT; // default port to listen

const corsOptions = {
   origin: '*', 
   credentials: true,  
   'access-control-allow-credentials': true,
   optionSuccessStatus: 200,
}

app.use(cors(corsOptions));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 3308
});


// Makes Express parse the JSON body of any requests and adds the body to the req object
app.use(bodyParser.json());

app.use(async (req, res, next) => {
  try {
    // Connecting to our SQL db. req gets modified and is available down the line in other middleware and endpoint functions
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;
    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    // Moves the request on down the line to the next middleware functions and/or the endpoint it's headed for
    await next();

    // After the endpoint has been reached and resolved, disconnects from the database
    req.db.release();
  } catch (err) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    console.log(err)
    // If an error occurs, disconnects from the database
    if (req.db) req.db.release();
    throw err;
  }
});

// code to add a new user to the database
app.put('/users', async (req, res) => {
    
    try {
        //get the data from the request to create a new user
        const {
            username,
            email,
            password
        } = req.body;

        //check if the email is being used
        const [[validateEmail]] = await req.db.query(`SELECT email FROM users WHERE email = :email`, { email });
        const [[validateUser]] = await req.db.query(`SELECT username FROM users WHERE username = :username`, { username });

        if (validateEmail) {
            res.send('email already in use');
        } else if (validateUser) {
            res.send('username already taken');
        } else {

            //hash their password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            //attempt to insert the data into the database
            const [insert] = await req.db.query(`INSERT INTO users (username, email, password) VALUES (:username, :email, :hashedPassword);`, 
            { username, email, hashedPassword});
            console.log(`user created successfully: username - ${username}, email - ${email}`)
            res.send(`user created successfully`)
        }
        
    } catch(error) {
        console.log(`error creating user ${error}`);
    }
}) // end user post



app.post("/signin", async (req, res) => {
    try {
        //initialize variables
        let userObj = {};
        const { login, password: userEnteredPassword } = req.body;
        const emailCheck = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/

        //if it is an email query based on the email, otherwise query based on username
        if (emailCheck.test(login)) {
            const [[user]] = await req.db.query(`SELECT * FROM users WHERE email = :login`, { login });
            userObj = user;
        } else {
            const [[user]] = await req.db.query(`SELECT * FROM users WHERE username = :login`, { login });
            userObj = user;
        }

        //check if the user data is empty
        if (!userObj) {
            res.json({err: 'user doesnt exist', success: false});
        } else {
            const hashedPassword = `${userObj.password}`
            const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);

            if (!passwordMatches) {
                res.json({ err: 'invalid credentials', success: false });
            } else {
                const payload = {
                    user_id: userObj.user_id,
                    username: userObj.username,
                  }

                  const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);
                  res.json({ jwt: jwtEncodedUser, success: true });
            }
        }
    } catch(error) {
        console.log("error checking sign in: ", error);
        res.json({err: error, success: false});
    }
})

//gets a list of all the users
//not intended to be used in final project, just for practicing and getting started
app.get('/users', async (req, res) => {
    const [users] = await req.db.query(`SELECT user_id, username, email FROM Users`)
    console.log(users);
    res.send(users);
}) 

app.listen(port, () => {
    console.log(`Server started listening on port ${port}`);
})