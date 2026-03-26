import express from "express";
// import { body } from "express-validator";
import rateLimit from "express-rate-limit";
import { register, login, getMe } from "../controllers/authController.js";
import { protect } from "../middleware/authMiddleware.js";
import { validate } from "../middleware/validationMiddleware.js";
import { registerValidation, loginValidation } from "../validations/authValidation.js";

import {
  forgotPassword,
  verifyOtp,
  resetPassword,
} from "../controllers/authController.js";

import {
  forgotPasswordValidation,
  verifyOtpValidation,
  resetPasswordValidation,
} from "../validations/authValidation.js";

const router = express.Router();

// ── Rate limiter: max 10 auth attempts per 15 mins per IP ─────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { message: "Too many attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});


// ── Routes ────────────────────────────────────────────────────────────────────
router.post("/register", authLimiter, registerValidation, validate, register);
router.post("/login", authLimiter, loginValidation, validate, login);
router.get("/me", protect, getMe);   // Protected example


router.post(
  "/forgot-password",
  authLimiter,
  forgotPasswordValidation,
  validate,
  forgotPassword
);

router.post(
  "/verify-otp",
  authLimiter,
  verifyOtpValidation,
  validate,
  verifyOtp
);

router.post(
  "/reset-password",
  authLimiter,
  resetPasswordValidation,
  validate,
  resetPassword
);



export default router;

