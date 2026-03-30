import jwt from "jsonwebtoken";
import { validationResult } from "express-validator";
import User from "../models/User.js";
import nodemailer from "nodemailer";

// ── Helper: generate JWT ─────────────────────────────
const generateToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
};

// ── REGISTER ─────────────────────────────────────────
const register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: errors.array()[0].msg,
    });
  }

  let { name, email, password } = req.body;

  try {
    email = email.trim().toLowerCase();

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email is already registered" });
    }

    const user = await User.create({ name, email, password });
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
    res.status(500).json({ message: "Server error" });
  }
};

// ── LOGIN ────────────────────────────────────────────
const login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: errors.array()[0].msg,
    });
  }

  let { email, password } = req.body;

  try {
    email = email.trim().toLowerCase();

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

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
    res.status(500).json({ message: "Server error" });
  }
};

// ── GET ME ───────────────────────────────────────────
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

// ── FORGOT PASSWORD ──────────────────────────────────
const forgotPassword = async (req, res) => {
  let { email } = req.body;

  try {
    email = email.trim().toLowerCase();

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        message: "If this email exists, an OTP has been sent.",
      });
    }

    // ❗ prevent OTP spam
    if (user.resetOtp && user.resetOtpExpire > Date.now()) {
      return res.status(200).json({
        message: "OTP already sent. Please check your email.",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.resetOtp = otp;
    user.resetOtpExpire = Date.now() + 10 * 60 * 1000;
    await user.save();

    console.log("Generated OTP:", otp);

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, // App Password
      },
    });

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset OTP",
        text: `Your OTP is: ${otp}`,
      });

      console.log("✅ OTP sent to:", email);
    } catch (mailError) {
      console.error("❌ Email failed:", mailError.message);
    }

    res.status(200).json({
      message: "If this email exists, an OTP has been sent.",
    });

  } catch (error) {
    console.error("Forgot password error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

// ── VERIFY OTP ───────────────────────────────────────
const verifyOtp = async (req, res) => {
  let { email, otp } = req.body;

  try {
    email = email.trim().toLowerCase();
    otp = otp.trim();

    const user = await User.findOne({ email })
      .select("+resetOtp +resetOtpExpire");

    console.log("Entered OTP:", otp);
    console.log("Stored OTP:", user?.resetOtp);

    if (
      !user ||
      !user.resetOtp ||
      user.resetOtp.toString() !== otp.toString() ||
      !user.resetOtpExpire ||
      new Date(user.resetOtpExpire).getTime() < Date.now()
    ) {
      return res.status(400).json({
        message: "Invalid or expired OTP",
      });
    }

    res.json({
      message: "OTP verified successfully",
    });

  } catch (error) {
    console.error("Verify OTP error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

// ── RESET PASSWORD ───────────────────────────────────
const resetPassword = async (req, res) => {
  let { email, otp, newPassword } = req.body;

  try {
    email = email.trim().toLowerCase();
    otp = otp.trim();

    const user = await User.findOne({ email }).select("+password");

    if (
      !user ||
      !user.resetOtp ||
      user.resetOtp.toString() !== otp.toString() ||
      !user.resetOtpExpire ||
      user.resetOtpExpire < Date.now()
    ) {
      return res.status(400).json({
        message: "Invalid or expired OTP",
      });
    }

    // ✅ Update password
    user.password = newPassword;

    // ✅ Clear OTP
    user.resetOtp = null;
    user.resetOtpExpire = null;

    await user.save();

    res.json({
      message: "Password reset successful",
    });

  } catch (error) {
    console.error("Reset password error:", error.message);
    res.status(500).json({ message: "Server error" });
  }
};

export {
  register,
  login,
  getMe,
  forgotPassword,
  verifyOtp,
  resetPassword,
};