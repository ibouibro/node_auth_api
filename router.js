import { Router } from 'express';
const router = Router();
import { query, escape } from './dbConnection';
import { signupValidation, loginValidation } from './validation';
import { validationResult } from 'express-validator';
import { hash as _hash, compare } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';

router.post('/register', signupValidation, (req, res, next) => {
    query(
`SELECT * FROM users WHERE LOWER(email) = LOWER(${escape(
req.body.email
)})`,
(err, result) => {
if (result.length) {
return res.status(409).send({
msg: 'This user is already in use!'
});
} else {
// username is available
    _hash(req.body.password, 10, (err, hash) => {
if (err) {
return res.status(500).send({
msg: ' : erreur 1'
});
} else {
// has hashed pw => add to database
    query(
`INSERT INTO users (name, email, password) VALUES (${req.body.name}, ${escape(
req.body.email
)}, ${escape(hash)})`,
(err, result) => {
if (err) {
throw err;
return res.status(400).send({
msg: ' : erreur 2'
});
}
return res.status(201).send({
msg: 'The user has been registerd with us!'
});
}
);
}
});
}
}
);
});


router.post('/login', loginValidation, (req, res, next) => {
    query(
`SELECT * FROM users WHERE email = ${escape(req.body.email)};`,
(err, result) => {
// user does not exists
if (err) {
throw err;
return res.status(400).send({
msg: err
});
}
if (!result.length) {
return res.status(401).send({
msg: 'Email or password is incorrect!'
});
}
// check password
    compare(
req.body.password,
result[0]['password'],
(bErr, bResult) => {
// wrong password
if (bErr) {
throw bErr;
return res.status(401).send({
msg: 'Email or password is incorrect!'
});
}
if (bResult) {
const token = sign({id:result[0].id},'the-super-strong-secrect',{ expiresIn: '1h' });
/*db.query(
`UPDATE users SET last_login = now() WHERE id = '${result[0].id}'`
);*/
return res.status(200).send({
msg: 'Logged in!',
token,
user: result[0]
});
}
return res.status(401).send({
msg: 'Username or password is incorrect!'
});
}
);
}
);
});
router.post('/get-user', signupValidation, (req, res, next) => {
if(
!req.headers.authorization ||
!req.headers.authorization.startsWith('Bearer') ||
!req.headers.authorization.split(' ')[1]
){
return res.status(422).json({
message: "Please provide the token",
});
}
const theToken = req.headers.authorization.split(' ')[1];
const decoded = verify(theToken, 'the-super-strong-secrect');
    query('SELECT * FROM users where id=?', decoded.id, function (error, results, fields) {
if (error) throw error;
return res.send({ error: false, data: results[0], message: 'Fetch Successfully.' });
});
});
export default router;
