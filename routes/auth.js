import express, { Router } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import pool from '../config/db.js'
import { protect } from '../middleware/auth.js'

const router = express.Router();

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000 //30days
}

const generateToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: '30d'
    } )
}

//Register

router.post('/register', async(req,res) => {
    const { name, email, password } = req.body;

    if( !name || !email || !password ){
        return res.status(400).json({message: "please provide all required fields"})
    }

    const userExists = await pool.query('SELECT * FROM users WHERE email = $1 ', [email]);

    if (userExists.rows.length > 0) {
        return res.status(400).json({message: 'User already exists' })
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
        'INSERT INTO users( name , email , password ) VALUES ( $1,$2,$3 ) RETURNING id, name, email',
        [ name, email, hashedPassword ]
    )

    const token = generateToken(newUser.rows[0].id);

    res.cookie('token',token,cookieOptions)

    return res.status(201).json({ user: newUser.rows[0] })

})

//Login

router.post('/login', async (req,res) => {
    const { email, password } = req.body

    if(!email || !password) {
        return res.status(400).json({message: "please provide all required fields"})
    }

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email] )

    if(user.rows.length === 0) {
        return res.status(400).json({message: 'Invalid credentials'})
    }

        const userData = user.rows[0]

        const isMatch = await bcrypt.compare(password , userData.password)

        if (!isMatch) {
            return res.status(400).json({message: 'Invalid credentioals'})
        }

        const token = generateToken(userData.id)

        res.cookie('token', token,cookieOptions)

        res.json({ user: { id: userData.id, username: userData.username, email: userData.email}})
    
})

//Me(user)
router.get('/me', protect, async(req,res) => {
    res.json(req.user)
    //returning info of the logged in user from protect middleware
})

//Logout
router.post('/logout', (req,res) => {
    res.cookie('token', '', {...cookieOptions, maxAge:1 })
    res.json({message: 'Logged out successfully'})
})

router.post('/', async(req,res) => {
    const { name,course,email } = req.body

    if( !name|| !course|| !email ) {
        return res.status(400).json({message: "please provide all required fields"})
    }

    const newStudent = await pool.query(
        'INSERT INTO student( name, course, email ) VALUES ( $1,$2,$3 ) RETURNING id, name, course',
        [name,course,email]
    )

    return res.status(201).json({ student: newStudent.rows[0] })
})


export default router