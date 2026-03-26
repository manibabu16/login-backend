// validations/authValidation.js
import { body } from "express-validator";

// ── Register Validation ───────────────────────────────────────────────
export const registerValidation = [
  body("name")
    .trim()
    .notEmpty().withMessage("Name is required")
    .isLength({ min: 2 }).withMessage("Name must be at least 2 characters"),

  body("email")
    .trim()
    .notEmpty().withMessage("Email is required")
    .isEmail().withMessage("Please enter a valid email")
    .normalizeEmail(),

  body("password")
    .notEmpty().withMessage("Password is required")
    .isLength({ min: 8 }).withMessage("Password must be at least 8 characters")
    .matches(/[A-Z]/).withMessage("Password must contain at least one uppercase letter")
    .matches(/[0-9]/).withMessage("Password must contain at least one number"),
];

// ── Login Validation ──────────────────────────────────────────────────
export const loginValidation = [
  body("email")
    .trim()
    .notEmpty().withMessage("Email is required")
    .isEmail().withMessage("Please enter a valid email")
    .normalizeEmail(),

  body("password")
    .notEmpty().withMessage("Password is required"),
];


export const forgotPasswordValidation = [
  body("email").isEmail().withMessage("Valid email required"),
];

export const verifyOtpValidation = [
  body("email").isEmail(),
  body("otp").isLength({ min: 6, max: 6 }).withMessage("OTP must be 6 digits"),
];

export const resetPasswordValidation = [
  body("email").isEmail(),
  body("otp").isLength({ min: 6, max: 6 }),
  body("newPassword")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters"),
];