import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
    firstName:{type:String, required:true},
    lastName:{type:String, required:true},
    profilePic:{ type:String, default:""}, //cloduinary image url
     profilePicPublicId: { type:String, default:""}, //cloduinary public_id for deletion
     email: {type: String, required: true},
     password: {type: String, required: true, unique:true},
     role: {
        type: String, 
        enum: ["user", "admin"],
        default: "user"
     },
     token: {type: String, default: null},
     isVerified: {type: Boolean, default: false},
     isLoggedIn: {type: Boolean, default: false},
     otp: {type: String, default: null},
     otpExpiry: {type: Date, default: null},
     address: {type: String},
     city: {type: String},
    zipCode: {type: String},
    phonNo: {type: String},
}, { timestamp: true })

export const User = mongoose.model("user", userSchema)