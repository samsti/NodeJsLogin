const AuthenticationStrategy = require('passport-local').Strategy;
const Encryption = require('bcrypt');

function initializeAuthentication(passport, fetchUserByEmail, fetchUserById) {
  const authenticateUser = async (email, password, done) => {
    const user = fetchUserByEmail(email);
    
    if (!user) {
      return done(null, false, { errorMessage: 'No user with that email' });
    }

    try {
      const isPasswordValid = await Encryption.compare(password, user.password);
      
      if (isPasswordValid) {
        return done(null, user);
      } else {
        return done(null, false, { errorMessage: 'Incorrect password' });
      }
    } catch (error) {
      return done(error);
    }
  };

  passport.use(new AuthenticationStrategy({ usernameField: 'email' }, authenticateUser));
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    const user = fetchUserById(id);
    return done(null, user);
  });
}

module.exports = initializeAuthentication;
