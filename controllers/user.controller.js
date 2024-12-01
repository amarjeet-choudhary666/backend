import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinay.js";
import { ApiResponse } from "../utils/ApiResponse.js";


const registerUser = asyncHandler(async(req, res) => {
    //get user details from frontend
    //validation - no empty
    ///check if user already exists: username: details
    //chack for images, avatar
    // upload on cloudinary , avatar
    // create user object - create entry in db
    // remove password and refresh token feild from response
    // checck the user creation
    // return response

    const {fullName, email, username, password} = req.body
    console.log("email", email);
    
    if([fullName, email, username, password].some((feild) => {
        feild?.trim() === ""
    })){
        throw new ApiError(400, "All feilds are required ")
    }

    const existedUser = User.findOne({
        $or: [{username}, {email}]
    })
    if(existedUser){
        throw new ApiError(409, "user is already exist")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files.coverImage[0]?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "avatar file is required")
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
        throw new ApiError(400, "avatar is rquired")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
        
    })

    const createUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createUser){
        throw new ApiError(500, "something went wrong while registration")
    }
    return res.status(201).json(
        new ApiResponse(200, createUser, "User registred successfully")
    )

})

export {registerUser};