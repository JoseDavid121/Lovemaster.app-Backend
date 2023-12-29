import {z} from 'zod'

export const registerSchema = z.object({
    username: z.string({
        required_error: 'Username is requerid'
    }),
    email: z.string({
        required_error: 'Email is requerid'
    }).email({
        message: 'Email is not valid'
    }),  
    password: z.string({
        required_error: 'Password is requerid',
    }).min(6, {
        message: "Password must be at last 6 characteres"
    })
})

export const loginSchema = z.object({
    email: z.string({
        required_error: "Email is requerid",
    }).email({
        message: "Email is not valid",
    }),
    password: z.string({
        required_error: "Password is requerid",
    }).min(6, {
        message: "Password must be at last 6 characters",
    }),
})