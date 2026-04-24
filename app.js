const express = require("express");
const path = require("path");
const cors = require("cors");

const iva = require("./iva");

const app = express();

app.use(cors());
app.use(express.json());

// frontend
app.use(express.static(path.join(__dirname, "public")));

// api
app.use("/api/ivasms", iva);

// root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`🔥 Server running: http://localhost:${PORT}`);
});