const jwt = require("jsonwebtoken");
require("dotenv").config();

// Middleware untuk memverifikasi token JWT dan mengautentikasi pengguna
const authenticateToken = (req, res, next) => {
  // Mengambil header 'Authorization' dari request
  const authHeader = req.headers["authorization"];
  // Memisahkan token dari format "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];

  // Jika token tidak ada, kirimkan status 401 Unauthorized
  if (!token) return res.sendStatus(401);

  // Memverifikasi token menggunakan secret dari environment variable
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    // Jika terjadi kesalahan saat verifikasi, kirimkan status 403 Forbidden
    if (err) return res.sendStatus(403);
    // Jika token valid, simpan informasi pengguna ke dalam objek request
    req.user = user;
    // Panggil middleware berikutnya
    next();
  });
};

// Middleware untuk mengotorisasi pengguna berdasarkan peran
const authorizeRole = (role) => {
  return (req, res, next) => {
    // Memeriksa apakah peran pengguna sesuai dengan peran yang diotorisasi
    if (req.user.peran_pengguna !== role) {
      // Jika tidak sesuai, kirimkan status 403 Forbidden
      return res.status(403).json({ message: "Forbidden" });
    }
    // Jika sesuai, panggil middleware berikutnya
    next();
  };
};

module.exports = { authenticateToken, authorizeRole };
