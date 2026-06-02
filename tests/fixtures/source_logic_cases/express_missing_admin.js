const express = require("express");
const router = express.Router();

router.get("/admin/export", (req, res) => {
  res.json(exportAllRecords());
});
