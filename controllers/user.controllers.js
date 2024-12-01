import mongoose from "mongoose";
import { verifyJWT } from "../middlewares/auth.middlewares.js";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        user.accessToken = accessToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    //get user details from fontend
    //get validation
    //check if user already exist; username, email
    //chack for images , check avatar
    //upload them to cloudinary, avatar
    //create user object - create entry in db
    //remove refresh token and password feild from response
    //check user creation
    //return res

    const {fullName, email, password, username} = req.body
    console.log(fullName, email, password, username);

    if([fullName, email, password, username].some((feild) => feild?.trim() === "")
    ){
        throw new ApiError(400, "all feilds are required")
    }

    const existerUser = await User.findOne({
        $or: [{username}, {email}]
    })

    if(existerUser){
        throw new ApiError(409, "user is already exist")
    }
    console.log(req.files);

    const avatarLocalPath = req.files?.avatar[0]?.path;
    if(!avatarLocalPath){
        throw new ApiError(400, "avatar file is required")
    }
    const coverImageLocalPath = req.files?.coverImage[0]?.path;
    

    const avatar = await uploadOnCloudinary(coverImageLocalPath)
    const coverImage = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar){
        throw new ApiError(400, "avatar is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })


    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500, "something webt wring while register")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "user registered successfully")
    )

} )

const loginUser = asyncHandler(async(req, res) => {
    //req body => data
    //username, email 
    //find the user => exist or not
    //password check
    //access and refresh token generate 
    //send cookie

    const {email, username, password} = req.body
    console.log(username, password);

    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }
    
    // Here is an alternative of above code based on logic discussed in video:
    // if (!(username || email)) {
    //     throw new ApiError(400, "username or email is required")
        
    // }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

const isPasswordValid = await user.isPasswordCorrect(password)

if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials")
    }

const {accessToken, refreshToken} = await generateAccessAndRefereshTokens(user._id)

const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200, 
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
        )
    )
})

const logOutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
        )

        const options = {
            httpOnly: true,
            secure: true
        }

        return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User is loggedOut successfully"))
})

const refreshAccessToken = asyncHandler(async(req, res) => {
    
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = verifyJWT(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.find(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401, "invalid refresh token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .cookies("accessToken", accessToken, options)
        .cookies("refreshToken", newRefreshToken, options)
        .json(200,
            {
                accessToken, refreshToken: newRefreshToken},
                "accessToken and refreshed"
            )
    } catch (error) {
        throw new ApiError(400, "INVALID REFRESH TOKEN")
    }

})

const changeCurrentPassword = asyncHandler(async(req, res) => {
    const {oldPassword, newPassword, confirmPassword} = req.body

    if(!(newPassword === confirmPassword)){
        throw new ApiError(400, "new password and confirm password are not same")
    }

    const user = await user.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(isPasswordCorrect){
        throw new ApiError(400, "invalid oldpassword")
    }
    
    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "password changed successfully"))

})

const getCurrentUser = asyncHandler(async(res, req) => {
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async(req, res) => {
    const {fullName, email} = req.body

    if(!fullName || !email){
        throw new ApiError(400, "All feilds required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName: fullName,
                email: email
            }
        },
        {new: true}
        ).select("-password")

        return res
        .json(new ApiResponse(200, user, "account user updated"))
})

const updateUserAvatar = asyncHandler(async(req, res) => {
    const avatarLocalPath = req.file?.path

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "error while uploading avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.file?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {
            new: true
        }
        ).select("-password")

        return res
        .json(new ApiResponse(200, user, "avatar updated successfully"))
    
})

const updateUsercoverImage = asyncHandler(async(req, res) => {
    const coverImageLocalPath = req.file?.path

    if(!coverImageLocalPath){
        throw new ApiError(400, "cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "error while updated avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.file?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {
            new: true
        }
        ).select("-password")

        return res
        .json(new ApiResponse(200, user, "coverImage updated successfully"))
    
})

const getUserChannel = asyncHandler(async(req, res) => {

    const {username} = req.params

    if (!username?.trim()) {
        throw new ApiError(400, "username doest exist")
    }

    const channel = await User.aggregate([
        {
        $match: {
            username: username.toLowerCase()
        }
    }, 
    {
        $lookup: {
            from: "subscriptions",
            localField: "_id",
            foreignField: "channel",
            as: "subscribers"
        },
        
    }, 
    {
        $lookup: {
            from: "subscriptions",
            localField: "_id",
            foreignField: "subscriber",
            as: "subscribedTo"
        }
    },
    {
        $addFields: {
            subscriberCount: {
                $size: "$subscribers"
            }, 
            channelSubscribedToCount: {
                $size: "$subscribedTo"
            },
            isSubscribed: {
                $cond: {
                    if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                    then: true,
                    else: false
                }
            }
        }
    },
    {
        $project: {
            fullName: 1,
            username: 1,
            subscriberCount: 1,
            channelSubscribedToCount: 1,
            avatar: 1,
            coverImage: 1,
            email: 1
        }
    }
])
console.log(channel);

if(!channel?.length){
    throw new ApiError(404, "channel doesnt exists")
}

return res
.json(new ApiResponse(200, channel[0], "user channel fetched successfully"))

})

const getWatchHistory = asyncHandler(async(req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "Watch history fetched successfully"
        )
    )
})



export {
    registerUser,
    loginUser,
    logOutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUsercoverImage,
    getUserChannel,
    getWatchHistory
}