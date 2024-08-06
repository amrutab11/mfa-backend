const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const session = require('express-session');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const User = require('./model/User'); // Create User model as shown below
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET_KEY;

const corsOptions = {
    origin: 'http://localhost:3000', // Your frontend URL
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization',
};

app.use(cors(corsOptions));


mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("DB connection Success"))
    .catch(err => console.error("DB connection error:", err));

const generateOTP = () => crypto.randomInt(100000, 999999).toString();

const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
};

const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).send('Forbidden');
            req.user = user;
            next();
        });
    } else {
        res.status(401).send('Unauthorized');
    }
};

const sendOTP = async (email, otp) => {
    const transporter = nodemailer.createTransport({
        service:"gmail",
        secure:false,
        port:587,
        auth: {
            user: 'amrutabelgaonkar11998@gmail.com', // Your email address
            pass: 'rxjr svnf ohkf cmoq'  // Your email password
        }
    });
    await transporter.sendMail({
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`
    });
};

app.post('/register', async (req, res) => {
    const { email ,password} = req.body;

    let user = await User.findOne({ email });

    if(!user){
        const otp = generateOTP();
        await sendOTP(email, otp);
        const hashedPassword = await bcrypt.hash(password, 10);

        user = new User({ email,password:hashedPassword, otp, isVerified:false, otpExpiration: Date.now() + 10 * 60 * 1000 }); // 10 mins validity
        await user.save();
        res.status(200).send('OTP sent to your email.');
    } else {
        res.status(400).send('User Already Exist');
    }

});

app.post('/verify-otp', async (req, res) => {
    const { email, password , otp } = req.body;
    const user = await User.findOne({ email });

    if (user && user.otp === otp) {
        user.otp = null;
        user.otpExpiration = null;
        user.isVerified = true;
        await user.save();
        res.send('User registered and logged in.');
    } else {
        if(!user.otp === otp){
            res.status(400).send('Invalid OTP.');
        }   
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Account is not verified.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid Password.' });
        }

        const token = generateToken(user._id);
        res.cookie('token', token, { httpOnly: true });

        res.json({ message: 'Login successful', isVerified: user.isVerified });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});


app.post('/logout', authenticateToken,(req, res) => {
    res.clearCookie('token');
    res.send('Logged out successfully.');
});

app.get('/session', authenticateToken, (req, res) => {
    res.send('Session active.');
});

app.listen(PORT, () => {
    console.log('Server running on port '+ PORT);
});
