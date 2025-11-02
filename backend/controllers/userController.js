import { User } from '../models/userModel.js';
import { Session } from '../models/sessionModel.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { verifyEmail } from '../emailVerify/verifyEmail.js';
import { sendOTPMail } from '../emailVerify/sendOTPMail.js';

export const register = async(req, res)=>{
    try {
        const {firstName, lastName, email, password} = req.body;
        if(!firstName || !lastName || !email || !password){
            return res.status(400).json({
                success:false,
                message: "All fields are required"
            })
        }
        const user = await User.findOne({ email})
        if(user){
            return res.status(400).json({
                success: false,
                message: "User already exists"
            })
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            firstName,
            lastName,
            email,
            password: hashedPassword
        })

        const token = jwt.sign({id: newUser._id}, process.env.SECRET_KEY, {expiresIn: '10m'}) 
        verifyEmail(token, email);
        newUser.token = token;
        await newUser.save();
        return res.status(201).json({
            success: true,
            message: "User registered successfully",
            user: newUser
        })
    } catch (error) {
        
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

export const verify = async(req, res)=>{
    try {
        const authHeader = req.headers.authorization;
        if(!authHeader || !authHeader.startsWith('Bearer ')){
            return res.status(400).json({
                success: false,
                message: "Unauthorized"
            })
        }
        const token = authHeader.split(' ')[1];
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.SECRET_KEY)
        } catch (error) {
            if(error.name === 'TokenExpiredError'){
                return res.status(400).json({
                    success: false,
                    message: "Token expired"
                })
            }
            return res.status(400).json({
                success: false,
                message: "Invalid token"
            })
        }

        const user = await User.findById(decoded.id)
        if(!user){
            return res.status(404).json({
                success: false,
                message: "User not found"
            })
        }
        user.token = null;
        user.isVerified = true;
        await user.save()
        return res.status(200).json({
            success: true,
            message: "Email verified successfully"
        })

    } catch (error) {
        return res.status(500).json({ 
            success: false,
            message: error.message
        })
    } 
}

export const reVerify = async(req, res)=>{
    try { // Corrected syntax: missing closing parenthesis for res.status(200).json({...}) before this catch block, leading to an immediate error.
        const { email } = req.body;
        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({
                success: false,
                message: "User not found"
            })
        }
         const token = jwt.sign({id: user._id}, process.env.SECRET_KEY, {expiresIn: '10m'}) 
        verifyEmail(token, email);
        user.token = token;
        await user.save();
        return res.status(200).json({
            success: true,
            message: "Verification email sent again successfully",
            token: user.token
        })    
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}

export const login = async(req, res)=>{
    try {
        const { email, password } = req.body;
        if(!email || !password){
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            })
        }
        const existingUser = await User.findOne({ email });
        if(!existingUser){
            return res.status(400).json({
                success: false,
                message: "User does not exist"
            })
        }
        const isPasswordValid = await bcrypt.compare(password, existingUser.password);
        if(!isPasswordValid){
            return res.status(400).json({
                success: false,
                message: "Invalid credentials"
            })
        }
        if(!existingUser.isVerified){
            return res.status(400).json({
                success: false,
                message: "Verify your email to login"
            })
        }

        // Generate JWT Token
        const token = jwt.sign({id: existingUser._id}, process.env.SECRET_KEY, {expiresIn: '7d'});
        const refreshToken = jwt.sign({id: existingUser._id}, process.env.SECRET_KEY, {expiresIn: '30d'});
        existingUser.isLoggedIn = true;
        await existingUser.save();

        // check for existing session and delete it
        const existingSession = await Session.findOne({ userId: existingUser._id });
        if(existingSession){
            await Session.deleteOne({ userId: existingUser._id });
        }

        // create new session        
        await Session.create({ userId: existingUser._id });
        return res.status(200).json({
            success: true,
            message: `Welcome back, ${existingUser.firstName}`,
            user: existingUser,
            accessToken: token,
            refreshToken
        })
 } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        })
    }
}



export const logout = async(req, res)=>{
    try {
        const userId = req.id;
        await Session.deleteOne({ userId });
    await User.findByIdAndUpdate(userId, { isLoggedIn: false });
    return res.status(200).json({
        success: true,
        message: "User logged out successfully"
    });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: error.message
    });
}
}

export const forgotPassword = async(req, res)=>{
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User not found"
            });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        user.otp = otp;
        user.otpExpiry = otpExpiry;

        await user.save();
        await sendOTPMail(otp, email)
        return res.status(200).json({
            success: true,
            message: "OTP sent to email successfully"
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
    });
}
}

export const verifyOTP = async(req, res)=>{
    try 
    {
        const { otp } = req.body;
        const email = req.params.email;
        if (!otp) {
            return res.status(400).json({
                success: false,
                message: "OTP is required"
            });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User not found"
            });
        }
        if (!user.otp || !user.otpExpiry) {
            return res.status(400).json({
                success: false,
                message: "OTP not generated or already expired"
            });
        }
        if (user.otpExpiry < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "OTP has expired please request a new one"
            });
        }

        if (user.otp !== otp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            });
        }
        user.otp = null;
        user.otpExpiry = null;
        await user.save();
        return res.status(200).json({
            success: true,
            message: "OTP verified successfully"
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
}

export const changePassword = async(req, res)=>{
        try {
            const { confirmPassword, newPassword } = req.body;
            const email = req.params.email;
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({
                    success: false,
                    message: "User not found"
                });
            }
            if (!confirmPassword || !newPassword) {
                return res.status(400).json({
                    success: false,
                    message: "All fields are required"
                });
            }
            if (confirmPassword !== newPassword) {
                return res.status(400).json({
                    success: false,
                    message: "Passwords do not match"
                });
            }
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedPassword;
            await user.save();
            return res.status(200).json({
                success: true,
                message: "Password changed successfully"
            });

        } catch (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }
}

export const allUser = async(_, res)=>{
    try {
        const users = await User.find();
        return res.status(200).json({
            success: true,
            users
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
}

export const getUserById = async(req, res)=>{
    try {
        const {userId} = req.params; //extract userId from req.params
        const user = await User.findById(userId).select('-password -otp -otpExpiry -token');
        if(!user){
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }
        return res.status(200).json({
            success: true,
            user
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
}

