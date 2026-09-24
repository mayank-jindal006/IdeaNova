const express = require("express");
const { Octokit } = require("@octokit/rest");

const app = express();
const octokit = new Octokit({ auth: "ghp_JBd0Kh8oOOL8dKLzdocJ2isAjIhKtJ0RlgLK" });

app.get("/repos", async (req, res) => {
  const { data } = await octokit.repos.listForAuthenticatedUser();
  res.json(data.map((r) => r.full_name));
});

app.listen(3000, () => console.log("listening on 3000"));