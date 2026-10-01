const GITHUB_TOKEN = "ghp_FAKE1234567890ABCDEFGHIJKLMNOPQRSTU";

const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.send("repoguard-test-node app running");
});

app.listen(3000, () => console.log("listening on 3000"));

module.exports = { GITHUB_TOKEN };
