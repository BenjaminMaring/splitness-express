TABLE OF CONTENTS FOR ENDPOINTS

***Only endpoints that dont require a jwt token are /signup /signin and /workouts/:id***

1. Users
    1. '/signup' 
        line 76-123 in index.js, and is a PUT request
        Is used to create a new user. takes in username, email, and password 
        This endpoint also creates and returns a jwt token to the front end

    2. '/signin'
        line 127-171 in index.js, and is a POST request
        Is used to validate users credentials so they can sign in. 
        Takes in login and password, where login can be either their username
        or email. Endpoint also creates a jwt token and returns it to the front end

    3. '/User' 
        Line 211-231 in index.js, and is a GET request
        is used to get user information. returns the user_id, username, email, and profile_pic

2. Workouts
    1. '/workouts/id
        Line 165 in index.js, is a POST request
        is used to get the data for a workout. This is before the verify jwt token, so that way people can share the workout with others who dont have an account, so they dont need to be signed in to view the data. If the document will still have public/private values and will redirect to a different page if they are not the owner and the doc is private

    2. '/workouts/recent'
        line 
        