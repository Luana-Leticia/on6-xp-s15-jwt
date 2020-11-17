const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;
const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcrypt');
const salt = bcrypt.genSaltSync(10);
const secretKey = process.env.SECRET_KEY;
const hash = bcrypt.hashSync(secretKey, salt);
const accountsCollection = require('../models/accountSchema')

passport.use(
    new LocalStrategy({
        usernameField: 'email',
        passwordField: 'senha',
        session: false
    }, (email, senha, done) => {
        accountsCollection.find({ email: email }, (error, user) => {
            if (!user) {
                return 'Usuário não existente';
            } else if (account.senha == senha) {
                done(null, user);
            } else {
                return 'Senha inválida';
            }
        });
        done(null, {})
    })
);

passport.use(
    new BearerStrategy((token, done) => {
        try {
            const payload = jwt.verify(token, hash);
            const usuario = accountsCollection.findById(payload.id);
            done(null, usuario, { token: token});
        } catch (error) {
            done(error);
        }
        
    })
);