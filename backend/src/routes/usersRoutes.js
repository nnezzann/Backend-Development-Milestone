import express from "express"
import { getUsers, signUp, login, confirm, refreshToken, logout } from "../controllers/usersControllers.js"
import { createUserModel } from "../models/User.js"
const createUserRoutes = (usersDB) => {
    const router = express.Router()
    const User = createUserModel(usersDB)
    router.get("/", getUsers(User))
    router.post("/register", signUp(User))
    router.post("/login", login(User))
    router.get("/confirm/:token", confirm(User))
    router.post("/refresh", refreshToken(User))
    router.post("/logout", logout(User))
    return router

}
export default createUserRoutes
