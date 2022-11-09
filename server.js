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
    origin: "https://super-toffee-87905c.netlify.app"
}))

let authorisation = (req,res,next)=>{
    console.log(req.headers);
    if(req.headers.authorisation){
        let decode = jwt.verify(req.headers.authorisation,process.env.SEC);
        if(decode){
            next()
        }else{
            res.status(401).json({message:"Unauthorized"});
        }
    }else{
        res.status(401).json({message:"Unauthorized"});
    }
}

app.get("/home",authorisation,async function(req,res){
    try {
        const connection= await mongoClient.connect(URL)
        const db = connection.db(DB)
        const resUser=await db.collection("products").find().toArray()
        console.log(resUser)
        await connection.close()
         res.status(200).json(resUser)
        } catch (error) {
         console.log(error)
        res.status(500).json({message:"something went wrong"})
       }
})

app.get("/viewproduct/:id",authorisation,async function(req,res){
     try {
     const connection= await mongoClient.connect(URL)

     const db=connection.db(DB)

     const view=await db.collection("products").findOne({_id:mongodb.ObjectId(req.params.id)});

     await connection.close()
     res.json(view)
     } catch (error) {
        console.log(error)
        res.status(500).json({message:"something went wrong"})
     }
})

// app.post("/user",async function(req,res){
//    try {
//     const connection= await mongoClient.connect(URL)
//     const db = connection.db(DB)
//     const create= await db.collection("products").insertOne(req.body)
//     await connection.close()
//      res.status(200).json({message:"data inserted"})
//     } catch (error) {
//      console.log(error)
//     res.status(500).json({message:"something went wrong"})
//    }
// })


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
        let hook=user.username
    if (user) {
        let compare =await bcrypt.compare(req.body.password, user.password)
        if(compare){
            let token=jwt.sign({_id:user._id},process.env.SEC,{expiresIn:"50m"})
            res.json({token,hook})
        }else {
            res.json({messsage:"password is wrong"})
        }
        // console.log(compare)
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

        const link = `https://super-toffee-87905c.netlify.app/Reset-Password/${id._id}/${token}`;
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
            from:process.env.FROM,
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