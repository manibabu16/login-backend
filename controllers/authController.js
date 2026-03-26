import jwt from "jsonwebtoken";
import { validationResult } from "express-validator";
import User from "../models/User.js";
import nodemailer from "nodemailer";

// ── Helper: generate JWT ──────────────────────────────────────────────────────
const generateToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
};

// ── @route  POST /api/auth/register ──────────────────────────────────────────
// ── @access Public
const register = async (req, res) => {
  // 1. Validate input
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: errors.array()[0].msg, // Return first error only
    });
  }

  const { name, email, password } = req.body;

  try {
    // 2. Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email is already registered" });
    }

    // 3. Create user (password hashed automatically via pre-save hook)
    const user = await User.create({ name, email, password });

    // 4. Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      message: "Account created successfully",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Register error:", error.message);
    res.status(500).json({ message: "Server error. Please try again." });
  }
};

// ── @route  POST /api/auth/login ──────────────────────────────────────────────
// ── @access Public
const login = async (req, res) => {
  // 1. Validate input
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: errors.array()[0].msg,
    });
  }

  const { email, password } = req.body;

  try {
    // 2. Find user — explicitly include password (it's hidden by default)
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      // Generic message — don't reveal if email exists or not
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // 3. Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // 4. Generate token
    const token = generateToken(user._id);

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Server error. Please try again." });
  }
};

// ── @route  GET /api/auth/me ──────────────────────────────────────────────────
// ── @access Private (requires token)
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    console.error("GetMe error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};


const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    // Don't reveal user existence (security best practice)
    if (!user) {
      return res.status(200).json({ message: "If this email exists, an OTP has been sent." });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.resetOtp = otp;
    user.resetOtpExpire = Date.now() + 10 * 60 * 1000; // 10 mins
    await user.save();

    // Mail config
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    try {
      await transporter.sendMail({
        to: email,
        subject: "Password Reset Code",
        text: `Your OTP is: ${otp}`,
      });
      console.info("Forgot password: OTP email sent for", email);
    } catch (mailError) {
      console.error("Forgot password email send failed:", mailError.message || mailError);
      // do not fail entire operation; the API should still be opaque for security
    }

    res.status(200).json({
      message: "If this email exists, an OTP has been sent.",
    });

  } catch (error) {
    console.error("Forgot password error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (
      !user ||
      user.resetOtp !== otp ||
      user.resetOtpExpire < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    res.json({ message: "OTP verified" });

  } catch (error) {
    console.error("Verify OTP error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email }).select("+password");

    if (
      !user ||
      user.resetOtp !== otp ||
      user.resetOtpExpire < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // Set new password (your pre-save hook will hash it)
    user.password = newPassword;

    // Clear OTP
    user.resetOtp = undefined;
    user.resetOtpExpire = undefined;

    await user.save();

    res.json({ message: "Password reset successful" });

  } catch (error) {
    console.error("Reset password error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

export { register, login, getMe, forgotPassword, verifyOtp, resetPassword };