const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
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

/*
*
*
* CHECK READEME.MD FOR TABLE OF CONTENTS FOR ENDPOINTS
*
*
*/

app.use(async (req, res, next) => {
  try {
    // Connecting to our SQL db. req gets modified and is available down the line in other middleware and endpoint functions
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;
    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    // Moves the request on down the line to the next middleware functions and/or the endpoint it's headed for
    next();

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

/* 
*   CODE FOR USERS
*   
*   API call to create a new user
*   API call to sign in and get user info
*   API call to delete a user
*   
*/
// code to add a new user to the database
app.put('/signup', async (req, res) => {
    try {
        //get the data from the request to create a new user
        const {
            username,
            email,
            password
        } = req.body;

        const defaultProfilePicture = fs.readFileSync(path.join(__dirname, 'pictures/profile-pic.jpg'));

        //check if the email is being used
        const [[validateEmail]] = await req.db.query(`SELECT email FROM users WHERE email = :email`, { email });
        const [[validateUser]] = await req.db.query(`SELECT username FROM users WHERE username = :username`, { username });

        if (validateEmail) {
            res.json({success: false, err: "Email already in use"});
        } else if (validateUser) {
            res.json({success: false, err: "Username already taken"});
        } else {

            //hash their password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            //attempt to insert the data into the database
            const insert = await req.db.query(`INSERT INTO users (username, email, password, profile_pic) 
                                                          VALUES (:username, :email, :hashedPassword, :defaultProfilePicture);`, 
            { username, email, hashedPassword, defaultProfilePicture});

            //need to query into the db to get the newly created users id, username, and profilepic
            const [userData] = await req.db.query(`SELECT user_id, username FROM Users WHERE username = :username`, {
                username
            });

            const payload = {
                user_id: userData[0].user_id,
                username: userData[0].username,
            }

            const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);
                
            res.json({ jwt: jwtEncodedUser, success: true, data: payload });
        }
    } catch(error) {
        res.json({success: false, err: error});
        console.log(`error creating user ${error}`);
    }
}) // end user post


// endpoint used for signing in to a users account
app.post("/signin", async (req, res) => {
    console.log("/signin hit");
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

        //if the userData is not empty, check the passwords
        } else {
            const hashedPassword = `${userObj.password}`
            const passwordMatches = await bcrypt.compare(userEnteredPassword, hashedPassword);

            //if the passwords dont match, res with a false success and err
            if (!passwordMatches) {
                res.json({ err: 'invalid credentials', success: false });
            } else {
                //if the passwords do match, create the payload for the jwt token
                const payload = {
                    user_id: userObj.user_id,
                    username: userObj.username
                  }

                  const jwtEncodedUser = jwt.sign(payload, process.env.JWT_KEY);
                  res.json({ jwt: jwtEncodedUser, success: true, data: payload });
            }
        }
    } catch(error) {
        console.log("error checking sign in: ", error);
        res.json({err: error, success: false});
    }
})

app.post('/workouts/workout/:id', async (req, res) => {

    //get the workout id
    const { id: workout_id } = req.params

    try {

        //try to query the db for the workout data

        const [[data]] = req.db.query(`SELECT workout_name, `, {
            workout_id
        });

        //chec if there is data, then check if the data is public. if it is public, then send the data
        if (!data) {
            res.json({success: false, err: "no workout found"});
            return;
        } else if (!data.public) {
            res.json({success: true, public: false})
            return;
        } else {
            res.json({ success: true, public: true, data: data})
        }
    } catch (err) {
        console.log(err)
        res.json({ success: false, err: err });
    }
})
 
//validates auth token to access database 
app.use(async function verifyJwt(req, res, next) {
    const { authorization: authHeader } = req.headers;
    
    //check for the header
    if (!authHeader) {
        res.json({success: false, err: "No authorization headers"});
        return;
    }
 
    //split the header to check if it has Bearer 
    const [scheme, jwtToken] = authHeader.split(' ');

    if (scheme !== 'Bearer') {
        res.json({success: false, err: 'Invalid authorization, invalid authorization scheme' });
        return 
    } 
    
    try {
        //decode the jwt and check if its valid
      const decodedJwtObject = jwt.verify(jwtToken, process.env.JWT_KEY);
  
      //add the payload in the jwt object onto the req obj so the payload can be used in future endpoints
      req.user = decodedJwtObject;
    } catch (err) {
      console.log(err);
      if (
        err.message && 
        (err.message.toUpperCase() === 'INVALID TOKEN' || 
        err.message.toUpperCase() === 'JWT EXPIRED')
      ) {
   
        req.status = err.status || 500;
        req.body = err.message;
        req.app.emit('jwt-error', err, req);
      } else {
        console.log("error")
        throw((err.status || 500), err.message);
      }
    }
   
    next();
  });
 
//endpoint to get user information
app.get('/user', async (req, res) => {
    console.log("/user hit");
    try {
        //get user id from req payload
        const { user_id } = req.user;

        const [[userData]] = await req.db.query(`SELECT user_id, username, email, profile_pic 
                                                 FROM Users 
                                                 WHERE user_id = :user_id`, {
                                                    user_id
                                                })

        if (!userData) {
            res.json({success: false, err: "no valid user data"})
        } else {
            res.json({success: true, user_data: userData})
        }
    } catch(err) {
        console.log(err);
        res.json({success: false, err: err})
    }
})

/* 
*   CODE FOR WORKOUTS
*   
*   API call to get Recent workouts
*   API call t0 get all workouts for a user
*   API call to create a workout
*   API call to delete a workout
*
*/

app.post('/workouts/recent', async (req, res) => {
    try {
        const { user_id } = req.user;
        console.log("/workouts/recent hit id: " + user_id)

        if (!user_id) {
            res.json({succes: false, err: "missing user_id"});
            return;
        }

        const [workoutData] = await req.db.query(`SELECT * 
                                                  FROM Workouts 
                                                  WHERE user_id = :user_id 
                                                  ORDER BY last_edited DESC
                                                  LIMIT 5`, {
                                                    user_id
                                                });

        if (!workoutData) {
            res.json({success: false, err: "No Recent Workouts"})
        } else {
            res.json({success: true, data: workoutData});
        }
    } catch (err) {
        // console.log(err);
        res.json({success: false, err: err})
    }
}) 

//gets all of the users workouts
app.post('/workouts/all', async (req, res) => {
    try {
        const { user_id } = req.user;
        console.log("/workouts/all hit id: " + user_id)

        if (!user_id) {
            res.json({succes: false, err: "missing user_id"});
            return;
        }

        const [workoutData] = await req.db.query(`SELECT * 
                                                  FROM Workouts 
                                                  WHERE user_id = :user_id AND deleted_flag = 0
                                                  ORDER BY last_edited DESC`, {
                                                    user_id
                                                });

        if (!workoutData) {
            res.json({success: false, err: "No Workouts"})
        } else {
            res.json({success: true, data: workoutData});
        }
    } catch (err) {
        // console.log(err);
        res.json({success: false, err: err})
    }
}) 

app.post('/workouts/new', async (req, res) => {
    try {
        //get user id
        const { user_id } = req.user;
        
        //create the date for the last_edited
        const date = new Date();

        //create new default workout
        const [query] = await req.db.query(`INSERT INTO Workouts (workout_name, weekly, public, user_id, last_edited)
                                            VALUES ("New Workout", false, false, :user_id, :date)`, {
                                                user_id, date
                                            })

        //get the most workout id of the just created workout
        const { insertId: workout_id } = query

        console.log(query.insertId); 
        
        //create the users access
         await req.db.query(`INSERT INTO workout_access (role, workout_id, user_id)
                             VALUES ("Admin", :workout_id, :user_id)`, {
                                workout_id, user_id
                             }) 

        res.json({success: true, workout_id: workout_id});
 
    } catch (err) {
        console.log(err);
        res.json({success: false, err: "Internal Server Error"});
    }
}) 

app.delete('/workouts/delete/:workout_id', async (req, res) => {
    try {
        const { workout_id } = req.params;

        req.db.beginTransaction();

        const [query] = await req.db.query(`UPDATE workouts
                                            SET deleted_flag = 1
                                            WHERE workout_id = :workout_id`, {
            workout_id
        });

        await req.db.query(`UPDATE workout_access
                            SET deleted_flag = 1
                            WHERE workout_id = :workout_id`, {
            workout_id
        });

        req.db.commit();

        res.json({success: true, msg: "Workout Successfully deleted"})
        
    } catch (err) {
        console.log(err);
        res.json({ success: false, err: "Internal Server Error"})
    }
})


//starts the server
app.listen(port, () => {
    console.log(`Server started listening on port ${port}`);
}) 