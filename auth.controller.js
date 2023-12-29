import User from '../models/user.model.js'
import bcrypt from 'bcryptjs'
import {createAccessToken} from '../lib/jwt.js'
import jwt from 'jsonwebtoken'
import { TOKEN_SECRET } from '../config.js';
import Subscription from '../models/subscription.model.js';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

export const register = async (req, res) => {
    const {email, password, username} = req.body;
    
    try {

        const userFound = await User.findOne({email})
        if(userFound) return res.status(400).json([ 'The email is already in use' ] );

        const passwordHash = await bcrypt.hash(password, 10)

        const newUser = new User ({
            username,
            email,
            password: passwordHash,
        }) 
        
        const userSaved = await newUser.save();
        const token = await createAccessToken({id: userSaved._id})
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'None',
            maxAge: 1000 * 60 * 60,
         });
        res.json({
            id: userSaved._id,
            username: userSaved.username,
            email: userSaved.email,
            createdAt: userSaved.createdAt,
            updatedAt: userSaved.updatedAt,
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
};


export const login = async (req, res) => {
    const {email, password} = req.body;

    try {
        const userFound = await User.findOne({ email });
        if (!userFound) return res.status(400).json({ message: "User not found"})

        const isMatch = await bcrypt.compare(password, userFound.password)
        if (!isMatch) return res.status(400).json({ message: "Incorrect password"})

        const token = await createAccessToken({id: userFound._id})

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 1000 * 60 * 60,
         });
        res.json({
            id: userFound._id,
            username: userFound.username,
            email: userFound.email,
            createdAt: userFound.createdAt,
            updatedAt: userFound.updatedAt,
            token: token,
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error interno del servidor" });
    }
};


export const logout = (req, res) => {
    res.cookie('token', "", {
        expires: new Date()
    })
    return res.sendStatus(200)
}


export const profile = async (req, res) => {
    const userFound = await User.findById(req.user.id)

    if (!userFound) return res.status(400).json ({
        message: "User not found"
    });

    return res.json({
        id: userFound._id,
        username: userFound.username,
        email: userFound.email,
        createdAt: userFound.createdAt,
        updatedAt: userFound.updatedAt,
    })
}

export const requestPasswordReset = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        const resetTokenExpiration = Date.now() + 3600000;

        user.resetToken = resetToken;
        user.resetTokenExpiration = resetTokenExpiration;
        await user.save();
        await sendResetEmail(user, resetToken);

        res.status(200).json({ message: 'Reset email sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: `Internal server error: ${error.message}` });
    }
};

export const sendResetEmail = async (user, resetToken) => {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'lovemasterinformation@gmail.com',
                pass: 'vegw lysf horp pzdv',
            },
        });

        const mailOptions = {
            from: 'lovemasterinformation@gmail.com',
            to: user.email,
            subject: 'Password recovery',
            text: `Hola ${user.username},\n\n` +
                `We have received a request to reset your password. ` +
                `Click the following link to complete the process:\n\n` +
                `http://lovemaster.app/reset-password?token=${resetToken}\n\n` +
                `This link will expire in 1 hour.\n\n` +
                `If you have not requested to reset your password, please ignore this email.`,
        };
        await transporter.sendMail(mailOptions);

        console.log('Correo de recuperación enviado a:', user.email);
    } catch (error) {
        console.error('Error al enviar el correo de recuperación:', error);
        throw error;
    }
};

export const resetPassword = async (req, res) => {
    const { resetToken, newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetToken,
            resetTokenExpiration: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        user.password = newPasswordHash;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};
  
export const updateUser = async (user) => {
    try {
        const userUpdate = await User.findOneAndUpdate({ _id: user.id }, user);

        try {
            console.log(userUpdate);
            if (userUpdate) {
                return { success: true, data: { ...userUpdate } };
            } else {
                return { success: false, message: "Usuario no encontrado" };
            }
        } catch (err) {
            console.error(err);
            return { success: false, message: "Ha ocurrido un error al actualizar el usuario" };
        }
    } catch (err) {
        return { success: false, message: "Ha ocurrido un error al editar al usuario" };
    }
}

export const checkSubscription = (user) => {
    try {
        const userWithSubscription = User.findOne({ _id: user.id, subscription: { $exists: true } });

        if (userWithSubscription) {
            return { hasSubscription: true };
        } else {
            return { hasSubscription: false };
        } 
    } catch (err) {
        res.status(500).json({ message: "Ha ocurrido un error al verificar la suscripción" });
    }
};

export const SubscriptionC = async(req, res) => {

    const { subscriptionID, custom_id} = req.body
    
    let newSubscription = new Subscription(
        { 
            subscriptionID,
            custom_id,
        })

        try {
            await newSubscription.save();
            res.json({ message: "Suscripción guardada con éxito", id: newSubscription._id });
        } catch (err) {
            console.error(err);
            res.status(500).json({ message: "Error al guardar la suscripción" });
        }
        
}

export const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    console.log('token', token);
  
    if (!token) {
      res.status(401).send('Authentication required.');
      return;
    }
  
    jwt.verify(token, TOKEN_SECRET, (err, decoded) => {
      if (err) {
        res.status(403).send('Invalid token.');
        return;
      }
      req.user = decoded;
      next();
    });
  };
  