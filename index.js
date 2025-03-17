require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const mysql = require("mysql2/promise");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

global.dbPromise = connectDB(); // Store the database connection promise

const app = express();
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const port = process.env.PORT || 3000;
const Joi = require("joi");

const expireTime = 3600000; // 1 hour in milliseconds

/* Secret info from .env */
const mongoUrl = process.env.MONGODB_URI;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

/* Database Connection */
async function connectDB() {
    const db = await mysql.createConnection({
        host: process.env.MYSQL_HOST,
        port: process.env.MYSQL_PORT,
        user: process.env.MYSQL_USER,
        password: process.env.MYSQL_PASSWORD,
        database: process.env.MYSQL_DATABASE,
        ssl: { rejectUnauthorized: false },
    });

    console.log("Connected to Aiven MySQL database.");
    return db;
}

connectDB()
    .then((connection) => {
        global.db = connection;
    })
    .catch((err) => {
        console.error("Database connection failed:", err);
    });

/* Session Setup */
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: { secret: mongodb_session_secret },
});

app.use(
    session({
        secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: false,
    })
);

/* Utility Function */
function escapeHTML(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

const isUserPartOfRoom = async (userId, chatRoomId) => {
    const [rows] = await global.db.execute(
        "SELECT * FROM Room_Member WHERE Person_ID = ? AND ChatRoom_ID = ?",
        [userId, chatRoomId]
    );
    return rows.length > 0; // Returns true if user is part of the room
};

// Middleware to check if the user is part of the room
async function checkRoomAuthorization(req, res, next) {
    const userId = req.session.userId;
    const groupId = req.params.groupId;

    if (!userId || !groupId) {
        return res.status(400).send("User or group ID is missing.");
    }

    try {
        const [result] = await global.db.execute(
            "SELECT * FROM Room_Member WHERE Person_ID = ? AND ChatRoom_ID = ?",
            [userId, groupId]
        );

        if (result.length === 0) {
            return res.status(403).send("You are not a member of this chat room.");
        }

        next();  // User is authorized to access the room
    } catch (err) {
        console.error("Error checking room authorization:", err);
        return res.status(500).send("An error occurred while checking room authorization.");
    }
}



/* Homepage */
app.get("/", async (req, res) => {
    if (req.session.authenticated) {
        var safeUserName = escapeHTML(req.session.username);
        res.send(`
            Hello, ${safeUserName}! <br>    
            <a href='/groups'>View My Groups</a> <br>
            <a href='/logout'>Logout</a>
        `);
    } else {
        res.send(`
            <a href='/signup'>Sign up</a> <br>
            <a href='/login'>Login</a>
        `);
    }
});

/* SIGNUP */
app.get("/signup", (req, res) => {
    res.send(`
        <h2>Signup</h2>
        <form action="/signup" method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Sign Up</button>
        </form>
        <a href="/">Back</a>
    `);
});

app.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;

    const schema = Joi.object({
        username: Joi.string().alphanum().min(3).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string()
            .min(10)
            .pattern(/[a-z]/, 'lowercase') // At least one lowercase letter
            .pattern(/[A-Z]/, 'uppercase') // At least one uppercase letter
            .pattern(/[0-9]/, 'number') // At least one number
            .pattern(/[\W_]/, 'special character') // At least one special character
            .required()
            .messages({
                'string.min': 'Password must be at least 10 characters long.',
                'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character.',
            }),
    });

    const validation = schema.validate({ username, email, password });
    if (validation.error) {
        return res.send("Invalid input. <a href='/signup'>Try again</a>");
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    try {
        await global.db.execute(
            "INSERT INTO Person (username, email, password_hash) VALUES (?, ?, ?)",
            [username, email, hashedPassword]
        );
        res.redirect("/login");
    } catch (err) {
        console.error("Signup error:", err);
        res.send("Error signing up.");
    }
});

/* LOGIN */
app.get("/login", (req, res) => {
    res.send(`
        <h2>Login</h2>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
        <a href="/">Back</a>
    `);
});

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const [users] = await global.db.execute("SELECT * FROM Person WHERE username = ?", [username]);

    if (users.length === 0) {
        return res.send("User not found. <a href='/login'>Try again</a>");
    }

    const user = users[0];

    if (await bcrypt.compare(password, user.password_hash)) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.userId = user.Person_ID;
        res.redirect("/");
    } else {
        res.send("Incorrect password. <a href='/login'>Try again</a>");
    }
});

/* LOGOUT */
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("/groups", async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send("Unauthorized. <a href='/login'>Login</a>");
    }

    const userId = req.session.userId;

    try {
        // Get the groups the user is in
        const [groups] = await global.db.execute(
            `SELECT CR.ChatRoom_ID, CR.group_name, 
                    (SELECT MAX(sent_date) FROM Message WHERE ChatRoom_ID = CR.ChatRoom_ID) AS latest_message_date,
                    (SELECT COUNT(*) FROM Message WHERE ChatRoom_ID = CR.ChatRoom_ID AND sent_date > IFNULL((SELECT last_viewed FROM Room_Member WHERE Person_ID = ? AND Chatroom_ID = CR.ChatRoom_ID), '2000-01-01')) AS unread_messages
            FROM Room_Member RM
            JOIN ChatRoom CR ON RM.Chatroom_ID = CR.ChatRoom_ID
            WHERE RM.Person_ID = ?`,
            [userId, userId]
        );

        // Update last viewed timestamp for unread messages (Mark them as read)
        await global.db.execute(
            "UPDATE Room_Member SET last_viewed = NOW() WHERE Person_ID = ?",
            [userId]
        );

        let html = `<h2>My Chat Groups</h2>`;
        html += `<p>Total Groups: ${groups.length}</p>`;
        html += `<button onclick="location.href='/createGroup'">Create New Group</button>`;

        if (groups.length > 0) {
            html += "<ul>";
            groups.forEach((group) => {
                html += `
                    <li>
                        <strong>${group.group_name}</strong> 
                        <br>Last Message: ${group.latest_message_date || "No messages yet"} 
                        <br>Unread Messages: ${group.unread_messages}
                        <br><a href='/messages/${group.ChatRoom_ID}'>View Chat</a>
                    </li>
                    <br>
                `;
            });
            html += "</ul>";
        } else {
            html += "<p>You are not in any chat groups.</p>";
        }

        res.send(html);
    } catch (err) {
        console.error("Error fetching groups:", err);
        res.send("Error loading groups.");
    }
});

app.get('/createGroup', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    const userId = req.session.userId;

    try {
        // Fetch all users except the currently logged-in user
        const [users] = await global.db.execute(
            "SELECT Person_ID, username FROM Person WHERE Person_ID != ?",
            [userId]
        );

        let html = `
            <h2>Create a New Chat Group</h2>
            <form action="/createGroup" method="post">
                <input name="group_name" type="text" placeholder="Group Name" required><br><br>
                <h3>Select Users to Add to the Group:</h3>
        `;

        // Generate checkboxes for each user
        users.forEach(user => {
            html += `
                <label>
                    <input type="checkbox" name="users[]" value="${user.Person_ID}">${user.username}
                </label><br>
            `;

        });

        html += `
                <br><button type="submit">Create</button>
            </form>
            <br>
            <a href="/groups">Back to Groups</a>
        `;

        res.send(html);
    } catch (err) {
        console.error("Error fetching users:", err);
        res.send("Error loading users.");
    }
});



/* CREATE GROUP */
app.post("/createGroup", async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send("Unauthorized");
    }

    const groupName = req.body.group_name;
    const userId = req.session.userId;
    const selectedUsers = req.body.users || []; // Get selected users, default to an empty array if none selected

    if (!groupName) {
        return res.status(400).send("Group name is required.");
    }

    try {
        // Insert the new group into the ChatRoom table
        const [result] = await global.db.execute(
            "INSERT INTO ChatRoom (group_name, start_date) VALUES (?, NOW())",
            [groupName]
        );

        // Get the newly created group's ID
        const newGroupId = result.insertId;

        // Insert the creator as a member of the group
        await global.db.execute(
            "INSERT INTO Room_Member (ChatRoom_ID, Person_ID) VALUES (?, ?)",
            [newGroupId, userId]
        );

        // Insert selected users into the Room_Member table
        for (const selectedUserId of selectedUsers) {
            await global.db.execute(
                "INSERT INTO Room_Member (ChatRoom_ID, Person_ID) VALUES (?, ?)",
                [newGroupId, selectedUserId]
            );
        }

        res.send("Group created! <a href='/groups'>Go to Groups</a>");
    } catch (err) {
        console.error("Error creating group:", err);
        res.send("Error creating group.");
    }
});



/* JOIN GROUP */
app.post("/joinGroup", async (req, res) => {
    if (!req.session.authenticated) return res.status(401).send("Unauthorized");

    const groupId = req.body.groupId;
    try {
        await global.db.execute(
            "INSERT INTO Room_Member (Chatroom_ID, Person_ID) VALUES (?, ?)",
            [groupId, req.session.userId]
        );

        res.send("Joined group! <a href='/groups'>Go back</a>");
    } catch (err) {
        console.error("Error joining group:", err);
        res.send("Error joining group.");
    }
});

app.get("/messages/:groupId", checkRoomAuthorization, async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send("Unauthorized");
    }

    const userId = req.session.userId;
    const groupId = req.params.groupId;

    try {
        const [groupNameResult] = await global.db.execute(
            "SELECT group_name FROM ChatRoom WHERE ChatRoom_ID = ?",
            [groupId]
        );

        if (groupNameResult.length === 0) {
            return res.status(404).send("Group not found.");
        }

        const groupName = groupNameResult[0].group_name;

        // Fetch users who are not in the group
        const [availableUsers] = await global.db.execute(
            `SELECT Person_ID, username FROM Person WHERE Person_ID NOT IN 
                (SELECT Person_ID FROM Room_Member WHERE ChatRoom_ID = ?)`,
            [groupId]
        );

        const [lastViewedResult] = await global.db.execute(
            "SELECT last_viewed FROM Room_Member WHERE Person_ID = ? AND ChatRoom_ID = ?",
            [userId, groupId]
        );

        const lastViewed = lastViewedResult.length > 0 ? lastViewedResult[0].last_viewed : "2000-01-01 00:00:00";

        const [messages] = await global.db.execute(
            `SELECT M.Message_ID, M.body_text, M.sent_date, P.username, M.Person_ID,
                    (SELECT GROUP_CONCAT(E.emoji SEPARATOR ' ') FROM EmojiReaction E WHERE E.Message_ID = M.Message_ID) AS reactions
            FROM Message M
            JOIN Person P ON M.Person_ID = P.Person_ID
            WHERE M.ChatRoom_ID = ?
            ORDER BY M.sent_date ASC`,
            [groupId]
        );

        let html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>${groupName}</title>
                <link rel="stylesheet" href="/style.css">
            </head>
            <body>
                <div class="chat-container">
                    <h2>${groupName}</h2>

                    <!-- Invite More People Section (At the top) -->
                    <form action="/inviteToGroup/${groupId}" method="post">
                        <select name="users[]" multiple>
        `;

        availableUsers.forEach((user) => {
            html += `
                <option value="${user.Person_ID}">${user.username}</option>
            `;
        });

        html += `
                        </select>
                        <br><button type="submit">Invite</button>
                    </form>
                    <br> <!-- Add some space between the form and the messages -->

                    <div id="chat-box">`;

        let unreadSeparatorAdded = false;

        messages.forEach((msg) => {
            const msgClass = msg.Person_ID === userId ? "sent" : "received";
            const isUnread = new Date(msg.sent_date) > new Date(lastViewed);

            if (isUnread && !unreadSeparatorAdded) {
                html += `<div class="unread-separator">Unread Messages Below</div>`;
                unreadSeparatorAdded = true;
            }

            const emojiImages = msg.reactions ? msg.reactions.split(' ').map(emoji => {
                return `<img src="/emojis/${emoji}.png" alt="${emoji}" class="emoji-image">`;
            }).join(' ') : 'No reactions yet';

            html += `
                <div class="message-container ${msgClass}">
                    <div class="message ${msgClass}">
                        <strong>${msg.username}</strong>: ${msg.body_text}
                        <br><small>${msg.sent_date}</small>
                        <div class="reactions">
                            ${emojiImages}
                        </div>
                        <button class="reaction-btn" data-message-id="${msg.Message_ID}">+</button>
                        <div class="emoji-picker" id="emoji-picker-${msg.Message_ID}" style="display: none;">
                            <img src="/emojis/thumbs_up.png" alt="thumbs_up" class="emoji-image" data-emoji="thumbs_up">
                            <img src="/emojis/thumbs_down.png" alt="thumbs_down" class="emoji-image" data-emoji="thumbs_down">
                        </div>
                    </div>
                </div>
            `;
        });

        html += `</div>`;

        html += `<a href="/groups">Back to Groups</a>`;
        html += `</div></body></html>`;

        res.send(html);
    } catch (err) {
        console.error("Error fetching messages:", err);
        res.send("Error loading messages.");
    }
});



app.post("/sendMessage/:chatRoomId", async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send("Unauthorized");
    }

    const chatRoomId = req.params.chatRoomId;
    const userId = req.session.userId;
    const { message } = req.body;

    if (!message || message.trim() === "") {
        return res.status(400).send("Message cannot be empty.");
    }

    try {
        await global.db.execute(
            "INSERT INTO Message (Person_ID, ChatRoom_ID, sent_date, body_text) VALUES (?, ?, NOW(), ?)",
            [userId, chatRoomId, message]
        );

        res.redirect(`/messages/${chatRoomId}`);
    } catch (err) {
        console.error("Error sending message:", err);
        res.status(500).send("Error sending message.");
    }
});

app.post("/inviteToGroup/:groupId", async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send("Unauthorized");
    }

    const groupId = req.params.groupId;
    const userId = req.session.userId;
    const invitedUsers = req.body.users || []; // Get selected users

    try {
        for (const userIdToAdd of invitedUsers) {
            // Insert each selected user into the Room_Member table
            await global.db.execute(
                "INSERT INTO Room_Member (ChatRoom_ID, Person_ID) VALUES (?, ?)",
                [groupId, userIdToAdd]
            );
        }

        res.send("People invited to the group! <a href='/messages/" + groupId + "'>Go to Chat</a>");
    } catch (err) {
        console.error("Error inviting users to group:", err);
        res.send("Error inviting users.");
    }
});


app.post("/addReaction/:messageId", async (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).send("Unauthorized");
    }

    const userId = req.session.userId;
    const messageId = req.params.messageId;
    const emoji = req.body.emoji;

    try {
        // Insert emoji reaction into the database
        await global.db.execute(
            "INSERT INTO EmojiReaction (Message_ID, Person_ID, emoji) VALUES (?, ?, ?)",
            [messageId, userId, emoji]
        );

        // Redirect back to the messages page to update the reactions
        res.redirect(`/messages/${req.params.groupId}`);
    } catch (err) {
        console.error("Error adding reaction:", err);
        res.status(500).send("Error adding reaction.");
    }
});





app.listen(port, () => {
    console.log("Server running on port " + port);
});
