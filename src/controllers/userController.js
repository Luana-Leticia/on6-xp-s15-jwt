const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcrypt');
const salt = bcrypt.genSaltSync(10);
const secretKey = process.env.SECRET_KEY;
const hash = bcrypt.hashSync(secretKey, salt);

function createToken () {
    const payload = {
        id: 'usuario.id'
    };
    return jwt.sign(payload, hash, { expiresIn: '1m'});
}

module.exports = {
    login: (request, response) => {
        const token = createToken();
        response.set('Authorization', token);
        response.status(204).send();
    }
}