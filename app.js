const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const compression = require("compression");
const { appConfig } = require("./config");
const { createPassword } = require("./src/utils/utils");
const app = express();

app.use((req, res, next) => {
  console.log("request url: ", req.url);
  next();
});
app.use((req, res, next) => {
  if (req.url.includes("/admin")) {
    req.url = req.url.replace("/admin", "");
  }
  if (req.url.includes("/api")) {
    req.url = req.url.replace("/api", "");
  }
  next();
});
// app.use(express.static("./dist"));
const allowedOrigins = appConfig.allowedOrigins
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  }, // 允许的源
  methods: "GET,POST", // 允许的 HTTP 方法
  allowedHeaders: "Authorization, Content-Type", // 允许的请求头
  credentials: true, // 允许传递凭据（如 cookies）
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(compression());
const pool = mysql.createPool(appConfig.dataBase);
// 响应统一格式化
function responseFormat(code = 200, data = [], msg = "ok") {
  const response = {
    code,
    data,
    msg,
  };
  return response;
}
// token生成
function generateAccessToken(user, key) {
  return jwt.sign(user, key, {
    expiresIn: "8h",
  });
}

// 返回10位格式时间戳
function getTimeSpan() {
  return String(parseInt(new Date().getTime() / 1000));
}

// 登录
app.post("/login", async (req, res) => {
  pool.getConnection((err, connection) => {
    if (err) {
      res.send(responseFormat(409, [], err.sqlMessage));
      return;
    }
    const data = req.body;
    let sql = `SELECT * FROM users WHERE uname = '${data.uname}'`;
    connection.query(sql, (err, result) => {
      if (!err) {
        if (result[0]) {
          const user = result[0];
          const salt = user.salt;
          const password = createPassword(data.password.trim() + salt);
          if (user.password !== password) {
            res.send(responseFormat(409, [], "用户名或密码错误"));
            return;
          }
          const userInfo = {
            token: null,
            userName: user.uname,
            name: user.name,
            id: user.id,
          };
          jwt.verify(user.token, user.token_key, (err, decoded) => {
            if (!err) {
              const time = getTimeSpan();
              if (time < decoded.exp) {
                userInfo.token = user.token;
                return res.send(responseFormat(200, userInfo));
              }
            }
            const key = data.uname + getTimeSpan();
            const token = generateAccessToken({ uname: data.uname }, key);
            sql = `UPDATE users SET token_key = '${key}', token='${token}' WHERE uname = '${data.uname}'`;
            connection.query(sql, (err, result) => {
              connection.release();
              if (!err) {
                userInfo.token = token;
                res.send(responseFormat(200, userInfo));
              } else {
                res.send(responseFormat(409, [], err.sqlMessage));
              }
            });
          });
        } else {
          res.send(responseFormat(409, [], "用户名不存在"));
        }
      } else {
        res.send(responseFormat(409, [], err.sqlMessage));
      }
    });
  });
});
// token远程核验
app.get("/check", authenticateToken, (req, res) => {
  return res.send(responseFormat());
});

// token验证
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.send(responseFormat(401, null, "需要登录,才能操作"));
  }
  pool.getConnection((err, connection) => {
    const sql = `select token_key from users WHERE token = '${token}'`;
    connection.query(sql, (err, result) => {
      connection.release();
      if (!err && result.length) {
        const key = result[0].token_key;
        jwt.verify(token, key, (err, decoded) => {
          if (!err) {
            const time = getTimeSpan();
            if (time < decoded.exp) {
              next();
            } else {
              return res.send(responseFormat(401, null, "token过期"));
            }
          } else {
            return res.send(responseFormat(401, null, "token过期"));
          }
        });
      } else {
        return res.send(responseFormat(401, null, "token无效"));
      }
    });
  });
}

app.listen(9060, () => {
  console.log("9060 is running");
});

// 服务器写法
// app.listen(process.env.PORT,function() {
//   console.log(process.env.PORT ,"is running");
// })
