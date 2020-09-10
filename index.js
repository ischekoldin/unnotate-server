require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


const app = express();

const router = require('./router');
const pool = require('./db/index');

app.use(router);

// middleware

let CORS_OPTIONS;

if (!process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
    CORS_OPTIONS = {
        origin: "http://localhost:3000",
        credentials: true,
        preflightContinue: true
    }
} else {
    CORS_OPTIONS = {
        origin: "https://unnotate-client.herokuapp.com",
        credentials: true,
        preflightContinue: true
    }
}

app.use(cors(CORS_OPTIONS));
app.use(express.json());
app.use(cookieParser());



app.post ("/signup", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        let usersWithThisNameOrEmail = await pool.query("SELECT * FROM users WHERE user_name = $1" +
            "OR user_email = $2", [name, email]);
        usersWithThisNameOrEmail = usersWithThisNameOrEmail.rowCount;


        if (usersWithThisNameOrEmail === 0) {
            const saltRounds = 10;
            await bcrypt.hash(password, saltRounds, function (err, hashedPassword) {
                pool.query ("INSERT INTO users (user_name, user_email, user_password) VALUES ($1, $2, $3)",
                    [name, email, hashedPassword]);
            });

            res.send('User successfully added');

        } else {
            res.send(`User with name ${name} or email ${email} already exists`);
        }
    } catch (err) {
        console.error(err.message);
    }
});

async function checkPassword (name, password) {
    try {
        const dbResponse = await pool.query("SELECT * FROM users WHERE user_name = $1", [name]);
        const numberOfUsers = dbResponse.rowCount;

        if (numberOfUsers === 1) {

            const hashedPassword = dbResponse.rows[0].user_password;
            const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);

            // check the password
            if (isPasswordCorrect) {
                return 'password is correct'
            } else {
                return new Error('password is incorrect')
            }

        } else {
            return new Error('user not found')
        }

    } catch (err) {
        console.error(err.message);
    }
}

app.post ("/login", async (req, res) => {

    const { name, password, rememberMe } = req.body;

    try {
        const dbResponse = await pool.query("SELECT * FROM users WHERE user_name = $1", [name]);
        const numberOfUsers = dbResponse.rowCount;

        if (numberOfUsers === 1) {

            const hashedPassword = dbResponse.rows[0].user_password;
            const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);

            // check the password
            if (isPasswordCorrect) {
               const accessToken = generateAccessToken({name});
               const refreshToken = await jwt.sign(name, process.env.REFRESH_TOKEN_SECRET);
               await refreshTokens.push(refreshToken);

               res.cookie('unnotateRememberMe', rememberMe, { httpOnly: false, sameSite: "lax"});
               res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: "lax"});
               res.json({ accessToken: accessToken, refreshToken: refreshToken });

            } else {
                res.send("Password is incorrect");
            }

        } else {
            res.send("User Database has been corrupted");
        }

    } catch (err) {
        console.error(err.message);
    }

});

let refreshTokens = [];


app.get("/token", (req, res) => {

    console.info(req.cookies);
    const refreshToken = req.cookies.refreshToken;
    //console.info(req.cookies);
    //const refreshToken = req.body.token;
    if (!refreshToken) return res.sendStatus(403);
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.send(err.message);
        const accessToken = generateAccessToken({name: user});
        console.log(accessToken);
        return res.json({accessToken: accessToken, name: user});
    });
});


app.delete("/logout", (req, res) => {
    console.log(refreshTokens);
    console.info(req.cookies);
    refreshTokens = refreshTokens.filter(token => token !== req.cookies.refreshToken);
    console.log(refreshTokens);
    res.sendStatus(204);
});


app.get("/notes", authenticateToken, async (req, res) => {

    const dbResponse = await pool.query("SELECT * FROM notes WHERE note_owner_name = $1", [req.user.name]);
    console.log(`Name to fetch notes for ${req.user.name}`);
    res.send(dbResponse);
});

app.post("/notes/add", authenticateToken, async (req, res) => {
    const {
        noteTitle,
        noteText,
        noteOwnerName,
        noteCreatedTime,
        noteModifiedTime
    } = req.body;

    try {
        const noteAddResponse = await pool.query(
            "INSERT INTO notes (note_title, note_created, note_modified, note_text, note_owner_name) VALUES ($1, $2, $3, $4, $5)",
            [noteTitle, noteCreatedTime, noteModifiedTime, noteText, noteOwnerName]
        );
        res.send(noteAddResponse);
    } catch (err) {
        console.error(err.message);
    }
});

app.post("/notes/delete", authenticateToken, async (req, res) => {
    const { noteId } = req.body;

    try {
        const deleteNoteResponse = await pool.query("DELETE FROM notes WHERE note_id=$1", [noteId]);
        res.send(deleteNoteResponse);
    } catch (err) {
        console.error(err.message);
    }
});

app.post("/notes/save_active", authenticateToken, async (req, res) => {

    try {
        if (req.body.activeNote.note_id) {
            const noteTitle = req.body.activeNote.note_title;
            const noteModified = req.body.activeNote.note_modified;
            const noteText = req.body.activeNote.note_text;
            const noteId = req.body.activeNote.note_id;
            const response = await pool.query("UPDATE notes SET note_title=$1, note_modified=$2, note_text=$3 WHERE note_id=$4", [noteTitle, noteModified, noteText, noteId]);
            res.send(response);
        }

    } catch (err) {
        console.error(err.message);
    }
});

app.post("/auth/change_password", async (req, res) => {
    const { user, currentPassword, newPassword } = req.body;

    try {
        const checkPasswordResponse = await checkPassword(user, currentPassword);
        if (checkPasswordResponse === 'password is correct') {
            const changePasswordResponse = await pool.query("UPDATE users SET user_password=$1 WHERE user_name=$2",
                [user, newPassword]);
        }
        res.sendStatus(200);
    } catch (err) {
        if (err.message === 'password is incorrect') return await res.send('password is incorrect');
        if (err.message === 'user not found') return await res.send('user not found');
        console.error(err.message);
    }
});

app.get ("/users", async (req, res) => {
    const dbUsers = await pool.query("SELECT * FROM users");
    res.json(dbUsers);
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    })
}


function generateAccessToken(user) {
    console.log(user);
    const TOKEN_EXPIRATION_TIME = '15m';
    return  jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: TOKEN_EXPIRATION_TIME });
}


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`The server is running on port ${PORT}`);
});
