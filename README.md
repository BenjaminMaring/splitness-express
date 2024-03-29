TABLE OF CONTENTS FOR ENDPOINTS

1. Users
    - '/signup' 
        line 68-115 in index.js, and is a PUT request
        Is used to create a new user. takes in username, email, and password 
        This endpoint also creates and returns a jwt token to the front end

    - '/signin'
        line 119-163 in index.js, and is a POST request
        Is used to validate users credentials so they can sign in. 
        Takes in login and password, where login can be either their username
        or email. Endpoint also creates a jwt token and returns it to the front end

    - '/User' 
        Line 203-223 in index.js, and is a GET request
        is used to get user information. takes in user_id and return the user_id, username, email, and profile_pic

2. Workouts
    - '/workouts
        