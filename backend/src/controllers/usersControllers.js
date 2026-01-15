
import bcrypt from "bcrypt"
import nodemailer from "nodemailer"
import dotenv from "dotenv"
import crypto from "crypto"
import jwt from "jsonwebtoken"
dotenv.config()

export const getUsers = (User) => async (req, res) => {
    try {
        const allUsers = await User.find()
        res.status(200).json(allUsers)
    } catch (error) {
        console.log("Error in controllers", error);
        res.status(500).json({ message: "Internal server error!" })

    }

}
export const signUp = (User) => async (req, res) => {
    try {
        if (!req.body) {
            return res.status(400).json({ message: "Fill in the required fields please!" })
        }
        let { name, password, email } = req.body
        let your_pass = password
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!name || !password || !email) {
            return res.status(400).json({ message: "Name password and email fields required !" })
        }
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Invalid email format" })
        }
        if (password.length < 8) {
            return res.status(400).json({ message: "Password must be at least 8 characters" })
        }

        password = await bcrypt.hash(password, (10))
        const emailToken = await crypto.randomBytes(64).toString("hex")
        const url = `http://localhost:5003/api/confirm/${emailToken}`
        const newUser = new User({ name, password, email, emailToken })
        await newUser.save()
        res.status(201).json({ name, your_pass, emailToken, message: "Account successfully created ! Welcome !" })
        let message = `Thank you for trying Niel's Hub .Click the link below to confirm your email as signed into our app`
        const transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            port: 587,
            secure: false,
            auth: {
                user: process.env.USER_NAME,
                pass: process.env.USER_PASS
            }

        })

        transporter.sendMail({
            from: "nezaniel@gmail.com",
            to: email,
            subject: "Email Confirmation",
            text: message,
            html: `<div style="
                    width: 300px; 
                    height: 300px; 
                    background-color: #F0F0F0; 
                    padding: 20px; 
                    font-family: Arial, sans-serif; 
                    color: #333;
                    box-shadow: 0 5px 20px rgba(0,0,0,0.3); 
                        border-radius: 10px;
                    ">
                        <p style="font-weight: 500; font-size: 18px;">${message}</p>
                        <p style="font-weight: 500; font-size: 15px;">Click here ⬇️ </p>
                        <a href="${url}"
                            style="display: inline-block;
                            text-decoration: none; 
                            padding: 10px 20px; 
                            background-color: green;
                            font-size: 18px;
                            color: white; 
                            margin-left: 0px;
                            border-radius: 8px;
                            font-weight: 500;">
                            Confirm
                        </a>
                </div>`


        }).then(() => {
            console.log("Email sent successfully ");
        }).catch((error) => {
            console.log("Email not sent", error)
            res.status(500).json({ message: "Internal server error" })
        })


    } catch (error) {
        console.log("Error in controllers", error);
        res.status(500).json({ message: "Internal server error!" })

    }

}
export const confirm = (User) => async (req, res) => {

    if (!req.params) {
        return res.status(400).json({ message: "Use the confirmation link sent your email" })
    }
    let emailToken = req.params.token
    let user = await User.findOne({ emailToken })
    try {
        if (!user) {
            res.status(404).json({ message: "User not found. Try signing up" })
        }
        else {
            user.emailConfirmed = true
            user.emailToken = null
            await user.save()
            res.status(200).json({ message: "Email Confirmed.Continue to the app" })
        }
    } catch (error) {
        console.error("Error in controllers", error)
        res.status(500).status({ message: "Internal server error" })

    }

}
export const login = (User) => async (req, res) => {
    if (!req.body) {
        return res.status(400).json({ message: "Please enter your credentials" })
    }
    let { name, password, email, } = req.body
    const user = await User.findOne({ email })
    let password_test = await bcrypt.compare(password, user.password)
    if (password_test) {
        if (user.emailConfirmed) {
            const token = jwt.sign({ userId: user._id, tokenVersion: user.tokenVersion }, process.env.AUTH_SECRET, { expiresIn: "1h" })
            const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_SECRET, { expiresIn: "14d" })
            user.refreshToken = refreshToken
            user.isLoggedIn = true
            await user.save()
            res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false, maxAge: 14 * 24 * 60 * 60 * 1000 })
            res.status(200).json({ token })
        }
        else {
            res.status(400).json({ message: "Email not confirmed.View your email first" })
        }
    }
    else {
        res.status(401).json({ message: "Invalid password ! Check password and try again" })
    }

}
export const authMiddleware = (User) => async (req, res, next) => {
    if (!req.headers) {
        return res.status(400).json({ message: "Invalid request format" })
    }
    const authHeader = req.headers.authorization
    if (!authHeader) {
        return res.status(400).json({ message: "No token provided" })
    }
    try {
        const token = authHeader.split(" ")[1]
        const decoded = jwt.verify(token, process.env.AUTH_SECRET)
        const user = await User.findById(decoded.userId)
        if (decoded.tokenVersion === user.tokenVersion && user.isLoggedIn === true) {
            req.user = decoded
            next();
        }
        else if (user.isLoggedIn === false) {
            res.status(401).json({ message: "Please login first" })
        }
        else {
            res.status(401).json({ message: "Token expired ! Refresh !!" })
        }

    } catch (error) {
        console.error("Error in Authentication", error)
        res.status(403).json({ message: "Invalid token" })
    }


}
export const refreshToken = (User) => async (req, res) => {
    try {
        console.log(req.cookies)
        if (!req.cookies) {
            res.status(400).json({ message: "Please login first" })
        }
        const refreshToken = req.cookies.refreshToken
        if (!refreshToken) {
            return res.status(401).json({ message: "No token provided" })
        }
        const payload = jwt.verify(refreshToken, process.env.REFRESH_SECRET)
        const user = await User.findById(payload.userId)
        if (!user) {
            return res.status(404).json({ message: "User not found" })
        }
        user.tokenVersion += 1
        const newAccessToken = jwt.sign({ userId: user._id, tokenVersion: user.tokenVersion }, process.env.AUTH_SECRET, { expiresIn: "1h" })
        await user.save()
        res.status(201).json({ newAccessToken })

    }
    catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Refresh Token expired" })
        }
        console.error("Error in refreshing", error)
        return res.status(403).json({ message: "Invalid Token" })


    }


}
export const logout = (User) => async (req, res) => {
    try {
        if (!req.cookies) {
            return res.status(401).json({ message: "Please login first" })
        }
        const refreshToken = req.cookies.refreshToken
        if (!refreshToken) {
            return res.status(400).json({ message: "No token provided" })
        }
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET)
        if (!decoded) {
            return res.status(403).json({ message: "Token not eligible" })
        }
        const user = await User.findById(decoded.userId)
        user.refreshToken = null
        user.isLoggedIn = false
        await user.save()
        res.status(200).json({ message: "User successfully logged out" })
    } catch (error) {
        console.log("Error logging out the user", error)
        res.status(500).json({ message: "Internal server error" })

    }



}

