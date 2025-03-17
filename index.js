require("./utils.js")
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
global.dbPromise = connectDB(); // Store the database connection promise

const app = express();

app.use(express.static('public'));

const port = process.env.PORT || 3000;

const Joi = require('joi')

const expireTime = 3600000 //1 hour in milliseconds

/* my secret info from env file */
const mongoUrl = process.env.MONGODB_URI;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* end of env secret info */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

async function connectDB() {
    const db = await mysql.createConnection({
        host: process.env.MYSQL_HOST,
        port: process.env.MYSQL_PORT, 
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        ssl: {
            rejectUnauthorized: false 
        }
    });

    console.log("Connected to Aiven MySQL database.");
    return db;
}
connectDB().then(connection => {
    global.db = connection; 
}).catch(err => {
    console.error("Database connection failed:", err);
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false
}
));

function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")  // Convert & to &amp;
        .replace(/</g, "&lt;")   // Convert < to &lt;
        .replace(/>/g, "&gt;")   // Convert > to &gt;
        .replace(/"/g, "&quot;") // Convert " to &quot;
        .replace(/'/g, "&#039;"); // Convert ' to &#039;
}

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        var safeUserName = escapeHTML(req.session.username);
        var html = `
    Hello, ${safeUserName}!
    <br>    
    <form action='members' method='get'>
    <button>Go to Members Area</button>
    </form>
    <form action='logout' method='get'>
    <button>Logout</button>
    </form>
    `;
    res.send(html);
        
    } else {
    var html = `
    <form action='signup' method='get'>
    <button>Sign up</button>
    </form>
    <form action='login' method='get'>
    <button>Login</button>
    </form>
    `;
    res.send(html);
    }
});

app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='name'>
    <br>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;

    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().required(),
            password: Joi.string().max(20).required()
        });
        const validationResult = schema.validate({username, email, password});

        if (validationResult.error != null){
            console.log(validationResult.error);
            res.redirect("/signup");
            return;
        }

        try {
            // Insert into MySQL database
            var hashedPassword = await bcrypt.hash(password, saltRounds);
            const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
            await db.execute(query, [username, email, hashedPassword])

            console.log("User added to MySQL database");

            req.session.authenticated = true;
            req.session.username = username;
            req.session.email = email;
            req.session.cookie.maxAge = expireTime;

            res.redirect('/')
        } catch (err) {
            console.error("Error inserting user:", err);
            res.send('Error creating account. <a href="/signup">Try again</a>');
        }

});

app.get('/chat', async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send('Unauthorized. Please <a href="/login">log in</a>.');
    }

    try {
        const [groups] = await db.execute(`
            SELECT g.id, g.name, 
                (SELECT MAX(sent_at) FROM messages WHERE group_id = g.id) AS last_message_time,
                (SELECT COUNT(*) FROM messages WHERE group_id = g.id AND sent_at > (SELECT last_logout FROM users WHERE id = ?)) AS unread_messages
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = ?
        `, [req.session.user_id, req.session.user_id]);

        let html = `<h2>Your Chat Groups</h2>`;
        html += `<p>Total Groups: ${groups.length}</p>`;
        html += `<ul>`;
        groups.forEach(group => {
            html += `<li>
                        <a href="/chat/${group.id}">${group.name}</a> 
                        - Last message: ${group.last_message_time || 'No messages yet'} 
                        - Unread: ${group.unread_messages}
                    </li>`;
        });
        html += `</ul>`;
        html += `<form action="/chat/create" method="post">
                    <input type="text" name="group_name" placeholder="New group name" required>
                    <button type="submit">Create Group</button>
                 </form>`;
        
        res.send(html);
    } catch (err) {
        console.error("Error fetching chat groups:", err);
        res.status(500).send("Error loading chat groups.");
    }
});

app.post('/chat/create', async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send('Unauthorized. Please <a href="/login">log in</a>.');
    }

    const groupName = req.body.group_name;
    if (!groupName || groupName.trim() === "") {
        return res.status(400).send("Group name cannot be empty.");
    }

    try {
        const [result] = await db.execute(`INSERT INTO groups (name) VALUES (?)`, [groupName]);
        const groupId = result.insertId;

        await db.execute(`INSERT INTO group_members (group_id, user_id) VALUES (?, ?)`, [groupId, req.session.user_id]);

        res.redirect('/chat');
    } catch (err) {
        console.error("Error creating chat group:", err);
        res.status(500).send("Error creating chat group.");
    }
});

app.get('/chat/:groupId', async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send('Unauthorized. Please <a href="/login">log in</a>.');
    }

    const groupId = req.params.groupId;

    try {
        const [group] = await db.execute(`SELECT name FROM groups WHERE id = ?`, [groupId]);
        if (group.length === 0) {
            return res.status(404).send("Group not found.");
        }

        const [isMember] = await db.execute(`SELECT * FROM group_members WHERE group_id = ? AND user_id = ?`, [groupId, req.session.user_id]);
        if (isMember.length === 0) {
            return res.status(403).send("You are not authorized to view this chat.");
        }

        const [messages] = await db.execute(`
            SELECT m.id, m.message, m.sent_at, u.username 
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.group_id = ?
            ORDER BY m.sent_at ASC
        `, [groupId]);

        let html = `<h2>Chat Group: ${group[0].name}</h2>`;
        html += `<ul>`;
        messages.forEach(msg => {
            html += `<li><strong>${msg.username}</strong>: ${msg.message} <small>(${msg.sent_at})</small></li>`;
        });
        html += `</ul>`;

        html += `<form action="/chat/${groupId}/send" method="post">
                    <input type="text" name="message" placeholder="Type a message" required>
                    <button type="submit">Send</button>
                 </form>`;

        res.send(html);
    } catch (err) {
        console.error("Error loading chat:", err);
        res.status(500).send("Error loading chat messages.");
    }
});

app.post('/chat/:groupId/send', async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send('Unauthorized. Please <a href="/login">log in</a>.');
    }

    const groupId = req.params.groupId;
    const message = req.body.message.trim();

    if (!message) {
        return res.status(400).send("Message cannot be empty.");
    }

    try {
        const [isMember] = await db.execute(`SELECT * FROM group_members WHERE group_id = ? AND user_id = ?`, [groupId, req.session.user_id]);
        if (isMember.length === 0) {
            return res.status(403).send("You are not authorized to send messages in this chat.");
        }

        await db.execute(`INSERT INTO messages (group_id, user_id, message) VALUES (?, ?, ?)`, [groupId, req.session.user_id, message]);

        res.redirect(`/chat/${groupId}`);
    } catch (err) {
        console.error("Error sending message:", err);
        res.status(500).send("Error sending message.");
    }
});


app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    if (!email || !password) {
        res.send('Invalid email/password combination. <br> <a href="/login">Try again</a>');
        return;
    }

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);

    if (validationResult.error) {
        res.send('Invalid email. <a href="/login">Try again</a>');
        return;
    }

    try {
        // Query user from MySQL database
        const db = await global.dbPromise;
        const [rows] = await global.db.execute(
            `SELECT username, password FROM users WHERE email = ?`,
            [email]
        );

        if (rows.length !== 1) {
            console.log("User not found");
            res.send('Invalid email/password combination. <a href="/login">Try again</a>');
            return;
        }

        const user = rows[0];

        if (await bcrypt.compare(password, user.password)) {
            console.log("Correct password");

            req.session.authenticated = true;
            req.session.username = user.username;
            req.session.email = email;
            req.session.cookie.maxAge = expireTime;

            res.redirect('/');
        } else {
            res.send('Invalid password. <a href="/login">Try again</a>');
        }
    } catch (err) {
        console.error("Error logging in:", err);
        res.send('Error logging in. <a href="/login">Try again</a>');
    }
});

app.get('/loginSubmit', (req,res) => {
    var html = 'Invalid email/password combination <br> <a href="/login">Try again</a>';
    res.send(html);
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 