# Secure Login System

A beginner-friendly secure login web application built with Node.js, Express and SQLite.

## Features
- User registration and login
- Password hashing with bcrypt (12 salt rounds)
- Server-side input validation
- Parameterized SQL queries to prevent SQL injection
- Session management with SQLite-backed sessions
- Session ID regeneration after successful login
- Logout and basic login rate limiting
- Security headers via Helmet

## Requirements
- Node.js 20 or newer
- npm

## Run locally
1. Extract this project folder.
2. Open a terminal inside `secure-login-system`.
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the server:
   ```bash
   npm start
   ```
5. Open this address in your browser:
   **http://localhost:3000**

To stop the server, press `Ctrl + C` in the terminal.

## Important
- The local link works only on the computer where the server is running.
- This is a college/demo project. Before production deployment, configure a strong `SESSION_SECRET`, HTTPS, secure cookies, CSRF protection, account verification, password reset and production-grade monitoring.
- For HTTPS deployment, set the session cookie `secure` option to `true`.
- Optional 2FA is not implemented in this starter version.
