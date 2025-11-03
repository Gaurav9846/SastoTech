import { Product } from '../models/productModel.js';

export const addProduct = async (req, res) => {
    try {
        const { productName, productDesc, productPrice, category, brand } = req.body;
        const userId = req.id;
        if(!productName || !productDesc || !productPrice || !category || !brand) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }
        //handle multiple image uploads
        let productImg = [];
        if (req.files && req.files.length > 0) {
           for(let file of req.files) {
               const dataUri = getDataUri(file);
               const result = await cloudinary.uploader.upload(dataUri, {
                   folder: "mern_products" //cloudinary folder name
               });
               productImg.push({
                   url: result.secure_url,
                   public_id: result.public_id
               });
           }
        }
        //create a product in DB
        const newProduct = await Product.create({
            userId,
            productName,
            productDesc,
            productPrice,
            category,
            brand,
        productImg //array of objects [{url, public_id}, ...]
        });
        return res.status(201).json({
            success: true,
            message: "Product added successfully",
            product : newProduct
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
}

export const getAllProduct = async (_, res) => {
    try {
        const products = await Product.find();
        if(!products) {
            return res.status(404).json({
                success: false,
                message: "No products found",
                products: []
            });
        }
        return res.status(200).json({
            success: true,
            products
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
};
