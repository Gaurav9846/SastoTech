import express from 'express';
import { register, verify, reVerify, login, logout, verifyOTP, changePassword, allUser} from '../controllers/userController.js';
import { isAuthenticated, isAdmin  } from '../middleware/isAuthenticated.js';
import { forgotPassword, getUserById, updateUser} from '../controllers/userController.js';
import { singleUpload } from '../middleware/multer.js';

const router = express.Router()

router.post('/register', register)
router.post('/verify', verify)
router.post('/reverify', reVerify)
router.post('/login', login)
router.post('/logout', isAuthenticated, logout)
router.post('/forgot-password',forgotPassword)
router.post('/verify-otp/:email', verifyOTP)
router.post('/change-password/:email', changePassword)
router.get('/all-user',isAuthenticated, isAdmin, allUser)
router.get('/get-user/:id', isAuthenticated, getUserById)
router.put('/update/:id', isAuthenticated, singleUpload, updateUser)

export default router;