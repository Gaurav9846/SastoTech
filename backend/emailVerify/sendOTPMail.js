import nodemailer from "nodemailer";
import dotenv from "dotenv/config"; 

export const sendOTPMail = (otp, email) => {
    const mailTransporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS,
        },
    });

   
    let mailDetails = {
        from: process.env.MAIL_USER, 
        to: email,
        subject: "Password Reset OTP",
       html: `<p>Your OTP for password reset is <strong>${otp}</strong></p>`
    };
    
    mailTransporter.sendMail(mailDetails, function (err, data) {
        if (err) {
            console.log("Error Occurs:", err.message); 
        } else {
            console.log("OTP sent successfully");
        }
    });
};