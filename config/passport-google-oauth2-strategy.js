const passport = require('passport');
const googleStrategy = require('passport-google-oauth').OAuth2Strategy;
const crypto = require('crypto');
const User = require('../models/user');

passport.use(new googleStrategy({
    clientID: '1052859533762-ri8115crugfu25a4rubc34sit1fd03tt.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'http://localhost:8000/auth/google/callback',
    },
    //profile has the info abt the user
    (accessToken, refreshToken, profile, cb)=>{
        User.findOne({email: profile.emails[0].value}).exec((err, user)=>{
            if(err){
                console.log(`${err} in google strategy passport`);
                return;
            }
            console.log(accessToken, refreshToken);
            console.log(profile);
            if(user){
                return cb(null, user);
            }else{
             

                //if user doesn't exist in the db we will create one
                User.create({
                    // name: profile.name,
                    name: profile.name.givenName + " " + profile.name.familyName,
                    email: profile.emails[0].value, //as their can be multiple emails we are taking the first one
                    password: crypto.randomBytes(20).toString('hex')

                },(err, user)=>{
                    if(err){
                        console.log(`${err} in creating user`);
                        return;
                    }
                    return cb(null, user);
                });
            }
        });
    }

));

module.exports = passport;