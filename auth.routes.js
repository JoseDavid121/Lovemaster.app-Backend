import {Router} from 'express'
import {
    login, 
    logout, 
    register, 
    profile,
    SubscriptionC,
    updateUser,
    checkSubscription,
    verifyToken, 
    resetPassword,
    requestPasswordReset,

} from '../controllers/auth.controller.js'
import {authRequired} from '../middleweres/validateToken.js'
import {validateSchema} from '../middleweres/validator.middleweres.js'
import {registerSchema, loginSchema} from '../schemas/auth.schema.js'

const router = Router()

router.post('/request-reset', requestPasswordReset);
router.post('/reset-password', resetPassword);
router.post('/register', validateSchema(registerSchema), register);
router.post('/login', validateSchema(loginSchema), login);
router.post('/logout', logout)
router.post('/subscription', SubscriptionC)
router.put('/updateUser', verifyToken, async (req, res) => {
    await updateUser(req.body.user, res);
});

router.get('/profile', authRequired, profile)
router.get('/check-subscription', verifyToken, async (req, res) => {
  try {
      const result = await checkSubscription(req.user);

      if (result.hasSubscription) {
          res.status(200).json(result);
      } else {
          res.status(200).json(result);
      }
  } catch (error) {
      res.status(500).json({ error: "Ha ocurrido un error al verificar la suscripción" });
  }
});


export default router