const express = require("express");
const app = express();
const cors = require("cors")
const mongodb = require("mongodb")
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv").config()
var nodemailer= require('nodemailer')
const mongoClient = mongodb.MongoClient
const URL = process.env.LINK
const DB = "capstone"


app.use((express.json()))  //middleware
app.use(cors({
    origin: "http://localhost:3000"
}))


app.post("/register", async function (req, res) {
    try {
        let connection = await mongoClient.connect(URL)
        let db = connection.db(DB)

        let salt = await bcrypt.genSalt(10);
        // console.log(salt)
        let hash = await bcrypt.hash(req.body.password, salt);
        // console.log(hash)
        req.body.password = hash

     await db.collection("userlogin").insertOne(req.body)
  
        await connection.close()
        res.json({ message: "user registered success" })

    } catch (error) {
        console.log(error)
        res.json(error)
    }
})

app.post("/login", async function (req, res) {
    try {
        let connection = await mongoClient.connect(URL);
        let db = connection.db(DB);
        let user = await db.collection("userlogin").findOne({ email: req.body.email })
    if (user) {
        let compare =await bcrypt.compare(req.body.password, user.password)
        // console.log(compare)
        if (compare) {
            res.json({message:"user login successfully"})
        } else {
            res.json({messsage:"password is wrong"})
        }
    }
    } catch (error) {
        console.log(error)
        res.json({messsage:"user not found"})
    }
})

app.post("/Reset", async function (req, res) {
    try {
        let connection = await mongoClient.connect(URL);
        let db = connection.db(DB);

        let id = await db.collection("userlogin").findOne({ email: req.body.email });
        let email = req.body.email
        // console.log(email);
        if (!id) {
            res.status(404).json({ message: "User Not Exists" });
        }
        let token = jwt.sign({ _id: id._id }, process.env.SEC, { expiresIn: '5m' });

        const link = `http://localhost:4000/Reset-Password/${id._id}/${token}`;
        console.log(link);
        
        //Send a link Via mail;
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user:process.env.FROM,
                pass:process.env.PASSWORD
            }
        });

        var mailOptions = {
            from:"midhunguvi@gmail.com",
            to: email,
            subject: 'Password Reset',
            text:"Click this Link Reset Your Password",
            html:`<Link to=${link} target="_blank">${link}</Link>`,
        };

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent:' + info.response);
            }
        });
        res.send(link);

    } catch (error) {
        res.status(500).json({ Message: 'Something Went Wrong' });
        console.log(error);
    }
})

//Update New Password;
app.post("/Reset-Password/:id/:token", async function (req, res) {
    const id = req.params.id
    const token = req.params.token
    try {

        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.password, salt);

        let connection = await mongoClient.connect(URL);
        let db = connection.db(DB);

        let compare = jwt.verify(token,process.env.SEC);
        console.log(compare);
        if (compare) {
            // let Person = await db.collection("userlogin").findOne({ _id: mongodb.ObjectId(`${id}`) })
            // if (!Person) {
            //     return res.json({ Message: "User Exists!!" });
            // }
            await db.collection("userlogin").updateOne({ _id: mongodb.ObjectId(`${id}`) }, { $set: { password: hash } });
            res.json({ Message: "Password Updated" });
        } 
        else {
            res.json({ Message: "URL TimeOut" })
        }
    } catch (error) {
        res.status(500).json({ Message: 'unauthorised' });
        console.log(error);
    }

})

app.listen(process.env.PORT||4000)