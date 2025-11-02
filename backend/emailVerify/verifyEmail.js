import nodemailer from "nodemailer";
import dotenv from "dotenv/config"; 
export const verifyEmail = (token, email) => {
   
    let mailTransporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS,
        },
    });

   
    let mailDetails = {
        from: process.env.MAIL_USER, 
        to: email,
        subject: "Email Verification",
        text: `Hi! There, you have recently visited 
        our website and entered your email. Please follow this link to verify your email
        :http://localhost:5173/verify/${token}`,
    };
    
    mailTransporter.sendMail(mailDetails, function (err, data) {
        if (err) {
            console.log("Error Occurs:", err.message); 
        } else {
            console.log("Email sent successfully");
        }
    });
};