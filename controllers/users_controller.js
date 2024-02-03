const bcrypt = require('bcrypt');
const User = require('../models/user');
const path = require('path');
const fs = require('fs');

module.exports.signIn = (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/users/profile');
    }
    return res.render('user_sign_in');
};

module.exports.signUp = (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/users/profile');
    }
    return res.render('user_sign_up');
};

module.exports.profile = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        return res.render('user_profile', { profile_user: user });
    } catch (err) {
        req.flash('error', 'User not found');
        return res.redirect('/');
    }
};

module.exports.update = async (req, res) => {
    try {
        if (req.user.id !== req.params.id) {
            throw new Error('Unauthorized!');
        }

        const user = await User.findById(req.params.id);

        User.uploadedAvatar(req, res, (err) => {
            if (err) {
                console.error(err);
                return res.redirect('back');
            }

            user.name = req.body.name;
            user.email = req.body.email;

            if (req.file) {
                if (user.avatar) {
                    fs.unlinkSync(path.join(__dirname, '..', user.avatar));
                }
                user.avatar = User.avatarPath + '/' + req.file.filename;
            }

            user.save();
            return res.redirect('back');
        });
    } catch (err) {
        req.flash('error', err.message || 'An error occurred during update.');
        return res.redirect('back');
    }
};

module.exports.create = async (req, res) => {
    try {
        const { name, email, password, confirm_password } = req.body;

        // Check if passwords match
        if (password !== confirm_password) {
            throw new Error('Passwords do not match');
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            req.flash('error', 'User with this email already exists');
            return res.redirect('back');
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create a new user
        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
        });

        req.flash('success', 'You have signed up, login to continue!');
        return res.redirect('/users/sign-in');
    } catch (err) {
        req.flash('error', err.message || 'An error occurred during sign-up.');
        return res.redirect('back');
    }
};

module.exports.createSession = (req, res) => {
    req.flash('success', 'Logged in successfully');
    return res.redirect('/');
};

module.exports.destroySession = (req, res) => {
    req.logout();
    req.flash('success', 'You have logged out');
    return res.redirect('/');
};
