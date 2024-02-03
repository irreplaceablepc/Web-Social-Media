    const bcrypt = require('bcrypt');
    const passport = require('passport');
    const LocalStrategy = require('passport-local').Strategy;
    const User = require('../models/user');

    passport.use(
        new LocalStrategy(
            {
                usernameField: 'email',
                passReqToCallback: true,
            },
            async (req, email, password, done) => {
                try {
                    const user = await User.findOne({ email: email });
    
                    if (!user || !(await bcrypt.compare(password, user.password))) {
                        req.flash('error', 'Invalid username/password');
                        return done(null, false);
                    }
    
                    return done(null, user);
                } catch (err) {
                    req.flash('error', err.message);
                    return done(err);
                }
            }
        )
    );

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user);
        } catch (err) {
            done(err);
        }
    });

    passport.checkAuthentication = (req, res, next) => {
        if (req.isAuthenticated()) {
            return next();
        }
        res.redirect('/user/sign-in');
    };

    passport.setAuthenticatedUser = (req, res, next) => {
        if (req.isAuthenticated()) {
            res.locals.user = req.user;
        }
        next();
    };

    module.exports = passport;
