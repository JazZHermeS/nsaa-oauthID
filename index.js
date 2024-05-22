//OIDC express session for storing data
const express = require('express')
const session = require('express-session')


const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken') //needed to create JWT
const CustomStrategy = require('passport-custom').Strategy //RADIUS

//TLS
const https = require('https');
const fs = require('fs');
const path = require('path');

//use .env for gitflow and will be in process.env.
const dotenv = require('dotenv')
dotenv.config()

//axios for GETs and POSTs 
const axios = require('axios')

//random secret por HMAC-SHA256
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const scrypt = require('scrypt-mcf'); //juanan

// needed to validate later the cookie
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy

// mysql
//var database = require('./database/database');
const sqlite3 = require('sqlite3').verbose()

// movidas OIDC
const openidClient = require('openid-client')
openidClient.custom.setHttpOptionsDefaults({
  timeout: 10000 // Aumentar el tiempo de espera a 10 segundos
});

// OIDC 0. Make then necessary requires in the top of the file
const { Issuer, Strategy: OpenIDConnectStrategy } = require('openid-client')


// RADIUS
const radius = require('radius');
const RadiusClient = require('node-radius-client');
const {
    dictionaries: {
      rfc2865: {
        file,
        attributes,
      },
    },
  } = require('node-radius-utils');
  const RADIUS_HOST =  process.env.RADIUS_HOST
  const RADIUS_SECRET = process.env.RADIUS_SECRET



// Create database
const db = new sqlite3.Database('database.db');
// Create table users
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    hashedpswd TEXT NOT NULL
  )`);
});
// Query search pswd
const query = 'SELECT hashedpswd FROM users WHERE username = ?';
const query2 = 'SELECT username FROM users WHERE username = ?';


async function main () {
  const app = express()
  const port = 3000
  
  app.use(cookieParser())
  app.use(logger('dev'))

  // Configuration of express session
  app.use(session({
    secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
    resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
    saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
  }))

    // OIDC 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
  const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)

  // OIDC 2. Setup an OIDC client/relying party.
  const oidcClient = new oidcIssuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: [process.env.OIDC_CALLBACK_URL],
    response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
  })

  // OIDC 3. Configure the strategy.
  passport.use('oidc', new OpenIDConnectStrategy({
    client: oidcClient,
    usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  }, (tokenSet, userInfo, done) => {
    console.log(tokenSet, userInfo)
    if (tokenSet === undefined || userInfo === undefined) {
      return done('no tokenSet or userInfo')
    }
    return done(null, userInfo)
  }))


  /// RADIUS PASSSPORT
  passport.use('radius', new CustomStrategy(
    async function (req, done) {
      const username = req.body.username
      const password = req.body.password

      const radiusClient = new RadiusClient({host: RADIUS_HOST})

      try {
        const response = await radiusClient.accessRequest({
          secret: RADIUS_SECRET,
          attributes: [
            [attributes.USER_NAME, username + "@upc.edu"],
            [attributes.USER_PASSWORD, password],
          ],
        })

        if (response.code === 'Access-Accept') {
          const user = {
            username: username,
            description: 'the "only" user that deserves to get to this server'
          }
          return done(null, user)
        }
      } catch (error) {
          console.error(error)
      }
      return done(null, false)
    }
  )
)



/*
Configure the local strategy for using it in Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
    async function (username, password, done){
	try {
		console.log('LLego aqui');
	        db.get(query,[username], async (err,row) => {
	            console.log('query hecha');
	            if (err) {
	            	return done(err);
	            } 
	            if (!row) { // this user does not exist
	                return done (null, false);
	            }
	            //row has the pswd of the user saved in the db
	            const { hashedpswd } = row; // TODO
		    // scrypt-mcf to match hash password and compare with db	
          	    const match = await scrypt.verify(password, hashedpswd);

		   // console.log('algo de la row', hashedpswd);
		    if( match ){
		    //if( hashedpswd === password ){
			    console.log('MATCH');

			return done(null, {username});
		    } else {
			return done(null, false);
		    }
	        }); 
    } catch (error) {
	    console.log('error query ');
	    return done(error);
	}
    }
));
/*	
  function (username, password, done) {
    if (username === 'walrus' && password === 'walrus') {
      const user = { 
        username: 'walrus',
        description: 'the only user that deserves to get to this server'
      }
      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
    }
    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
));
  }*/


// validate the cookie
passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => {
      if (req && req.cookies) { return req.cookies.jwt }
      return null
    },
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    if (jwtPayload.sub) {
	    console.log('next step')
      if(jwtPayload.git!= true){
        db.get(query2, [jwtPayload.sub], async (err,row)=>{
            if(err){
                console.error('Error query user db', err.message);
                return done(err,false);
            }
		console.log('algo sale mal en el if', row, jwtPayload.sub);
            if(row && row.username === jwtPayload.sub){
	  //  console.log('next step 3')
               const user = { 
                 username: jwtPayload.sub,
                 description: 'one of the users that deserve to get to this server',
                 role: jwtPayload.role ?? 'user'
               };
               return done(null, user) 
            } else {
               return done(null, false)   
            }
          }
      );
    } else { // for github user authentication
      const user = { 
        username: jwtPayload.sub,
        description: 'one of the users that deserve to get to this server',
        role: jwtPayload.role ?? 'user'
      };
      console.log('hemos hecho la cookie');
      return done(null, user) 
    }
  } else {
        return done (null, false);
    }
  }
));


app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)

 // We will store in the session the complete passport user object
 passport.serializeUser(function (user, done) {
  return done(null, user)
})

// The returned passport user is just the user object that is stored in the session
passport.deserializeUser(function (user, done) {
  return done(null, user)
})

app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

// Route hadler for OAtuth singin GITHUB
app.get('/oauth2cb', async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
  /**
   * 1. Retrieve the authorization code from the query parameters
   */
  const code = req.query.code // Here we have the received code
  if (code === undefined) {
    const err = new Error('no code provided')
    err.status = 400 // Bad Request
    throw err
  }

  /**
   * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
   */
  const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
    client_id: process.env.OAUTH2_CLIENT_ID,
    client_secret: process.env.OAUTH2_CLIENT_SECRET,
    code
  })

  console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.

  // Let us parse them ang get the access token and the scope
  const params = new URLSearchParams(tokenResponse.data)
  const accessToken = params.get('access_token')
  const scope = params.get('scope')

  // if the scope does not include what we wanted, authorization fails
  if (scope !== 'user:email') {
    const err = new Error('user did not consent to release email')
    err.status = 401 // Unauthorized
    throw err
  }

  /**
   * 3. Use the access token to retrieve the user email from the USER_API endpoint
   */
  const userDataResponse = await axios.get(process.env.USER_API, {
    headers: {
      Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
    }
  })
  console.log(userDataResponse.data)

  /**
   * 4. Create our JWT using the github email as subject, and set the cookie.
   */
    // Let us parse them ang get the access token and the scope
    const params2 = new URLSearchParams(userDataResponse.data)
    const gitHubEmail = params2.get('email')

    // This is what ends up in our JWT
    const jwtClaims = {
      sub: gitHubEmail,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user', // just to show a private JWT field
      git: true
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')
    
    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password.
})


// Route handler for OIDC
app.get('/oidc/cb', passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }), (req, res) => {
  /**
 * Create our JWT using the req.user.email as subject, and set the cookie.
  */
  // This is what ends up in our JWT
  console.log("IMPRESION DEL PROFILE");
  console.log(req.user.given_name);
  const jwtClaims = {
    //sub: req.user.email
    sub: req.user.given_name,
    exm: req.user.family_name,
    iss: 'localhost:3000',
    aud: 'localhost:3000',
    exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
    role: 'user', // just to show a private JWT field
    git: true
  }

  // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
  const token = jwt.sign(jwtClaims, jwtSecret)

  // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
  //res.json(token)
  res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
  res.redirect('/')

  // And let us log a link to the jwt.io debugger for easy checking/verifying:
  console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
  console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
 // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password. The only difference is that now the sub claim will be set to req.user.email
})


// Route handler RADIUS
app.post('/login-radius',
        passport.authenticate('radius', { session: false, failureRedirect: '/login' }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
        (req, res) => {
                // This is what ends up in our JWT
            const jwtClaims = {
              sub: req.user.username,
              iss: 'localhost:3000',
              aud: 'localhost:3000',
              exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
              role: 'user', // just to show a private JWT field
              git: true
            }

            // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
            const token = jwt.sign(jwtClaims, jwtSecret)

            res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
            res.redirect('/')

            // And let us log a link to the jwt.io debugger for easy checking/verifying:
            console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
            console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
        }
    )

/*
app.get('/', (req, res) => {
  res.send('Welcome to your private page, user!')
})
*/
// forse use of authentication JWT cookie
app.get('/',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
  }
)

// sing in page to create account
app.get('/singin',
  (req, res) => {
    res.sendFile('singin.html', { root: __dirname })
  }
)

app.post('/singin',
    async (req, res)=> {
    const {username, password} = req.body;
    try {
        //hash password
        const hashed = await scrypt.hash(password, {scryptParams : { logN: 19, r: 8, p: 1 }});
        //insert user
        const query = 'INSERT INTO users (username, hashedpswd) VALUES (?,?)';
        db.run(query, [username, hashed], (err)=> {
            if(err){
                console.error('Error insert DB user ',err);
                return res.status(500).send('Error sing in user');
            }
            res.send('Successful sing in');
            console.log('Successful sing in');
        });
    } catch (error) {
        console.error('Error hash', error);
        res.status(500).send('Error hash');
    
    }
})

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')
    
    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

// OIDC endpoint: oidc strategy detects that it is the login endpoint and redirects to the authorization endpoint of the OIDC Provide
app.get('/oidc/login',
  passport.authenticate('oidc', { scope: 'openid profile' })
)

app.get('/logout',
  passport.authenticate(
    'jwtCookie',
    { session: false, failureRedirect: '/login' }
  ),
  (req, res) => { 
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: "", 
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) // Now
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    //res.json(token)
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
   // res.redirect('/')
	  
    res.sendFile('logout.html', { root: __dirname })
    
    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

/*
//TLS 
const serverOptions = {
  key: fs.readFileSync(path.join(__dirname, 'server.key')),
  cert: fs.readFileSync(path.join(__dirname, 'server.crt')),
//  passphrase: 'jazminnsa'
};

https.createServer(serverOptions, (req, res) => {
  res.writeHead(200);
  res.end('Hello, HTTPS World!');
}).listen(443, () => {
  console.log('Server is running on port 443');
});
/*
const server = https.createServer(serverOptions, app);
server.listen(port, () => {
  console.log(`Example app listening at https://localhost:${port}`);
});
*/
// error haddlers
app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
}

main().catch(e => { console.log(e) })