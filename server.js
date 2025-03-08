const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const db = new sqlite3.Database('./database.db');

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static('public'));

app.use(session({
  secret: 'mi_secreto_super_seguro',
  resave: false,
  saveUninitialized: false
}));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'TU CORREO ELECTRONICO',
    pass: 'TU CONTRASEÑA SEGURA'
  }
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      banned INTEGER DEFAULT 0,
      resetToken TEXT,
      resetTokenExpiration INTEGER
    )
  `);
});


app.get('/admin-login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin_login.html'));
});

app.post('/admin-login', (req, res) => {
  const { user, password } = req.body;
  if (user === 'EL NOMBRE DEL ADMIN' && password === 'LA CONTRASEÑA DEL ADMIN') {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  } else {
    return res.redirect('/admin-login?error=invalid');
  }
});



app.get('/admin', (req, res) => {
  if (!req.session.isAdmin) {
    return res.send("No eres administrador o no has iniciado sesión como admin.");
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/data', (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(401).json({ error: "No eres administrador" });
  }
  db.all("SELECT id, username, email, banned FROM users", (err, rows) => {
    if (err) {
      return res.status(500).json({ error: "Error al obtener usuarios" });
    }
    res.json(rows);
  });
});

app.post('/admin/ban/:id', (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(401).send("No eres administrador.");
  }
  const userId = req.params.id;
  db.run("UPDATE users SET banned = 1 WHERE id = ?", [userId], function (err) {
    if (err) {
      return res.status(500).send("Error al banear usuario.");
    }
    return res.json({ success: true });
  });
});

app.post('/admin/unban/:id', (req, res) => {
  if (!req.session.isAdmin) {
    return res.status(401).send("No eres administrador.");
  }
  const userId = req.params.id;
  db.run("UPDATE users SET banned = 0 WHERE id = ?", [userId], function (err) {
    if (err) {
      return res.status(500).send("Error al desbanear usuario.");
    }
    return res.json({ success: true });
  });
});

// GET /logout-admin -> Cierra sesión admin
app.get('/logout-admin', (req, res) => {
  req.session.isAdmin = false;
  res.send("Sesión de administrador cerrada. <a href='/'>Volver</a>");
});

app.post('/register', (req, res) => {
  const { username, email, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.redirect('/?error=mismatch');
  }
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.redirect('/?error=hashfail');
    }
    const stmt = db.prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    stmt.run(username, email, hashedPassword, (err) => {
      if (err) {
        return res.redirect('/?error=registerfail');
      }
      return res.redirect('/?success=registered');
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err || !user) {
      return res.redirect('/?error=invalid');
    }
    if (user.banned === 1) {
      return res.redirect('/?error=banned');
    }
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.redirect('/?error=invalid');
      }
      req.session.userId = user.id;
      req.session.username = user.username;
      return res.redirect('/dashboard');
    });
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Dashboard - KayyShop</title>
      <link
        href="https://fonts.googleapis.com/css?family=Poppins:300,400,500,600&display=swap"
        rel="stylesheet"
      />
      <style>
        :root {
          --color-primary: #4c76e2;
          --color-secondary: #49d295;
          --bg-gradient: linear-gradient(120deg, var(--color-primary), var(--color-secondary));
          --white: #fff;
          --dark: #333;
          --radius: 10px;
          --shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
        }
        body {
          margin: 0;
          padding: 0;
          font-family: 'Poppins', sans-serif;
          background: var(--bg-gradient);
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          position: relative;
          color: var(--white);
        }
        .dashboard-container {
          background: rgba(255, 255, 255, 0.15);
          backdrop-filter: blur(12px);
          border-radius: var(--radius);
          box-shadow: var(--shadow);
          padding: 2rem 3rem;
          text-align: center;
          animation: fadeIn 0.6s ease forwards;
        }
        @keyframes fadeIn {
          from {
            transform: translateY(30px);
            opacity: 0;
          }
          to {
            transform: translateY(0);
            opacity: 1;
          }
        }
        h1 {
          margin-bottom: 1rem;
          color: #fff;
        }
        p {
          margin-bottom: 2rem;
          color: #e2e2e2;
        }
        button {
          padding: 0.8rem 1.5rem;
          background: var(--color-primary);
          border: none;
          border-radius: var(--radius);
          color: var(--white);
          font-size: 1rem;
          cursor: pointer;
          transition: background 0.3s, transform 0.3s;
        }
        button:hover {
          background: var(--color-secondary);
          transform: scale(1.05);
        }
      </style>
    </head>
    <body>
      <div class="dashboard-container">
        <h1>¡Hola, ${req.session.username}!</h1>
        <p>Bienvenido a tu Dashboard de usuario.</p>
        <button onclick="location.href='/logout'">Cerrar sesión</button>
      </div>
    </body>
    </html>
  `);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// GET / -> Página principal (index.html)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/forgot-password', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8" />
      <title>Recuperar Contraseña</title>
      <link
        href="https://fonts.googleapis.com/css?family=Poppins:300,400,500,600&display=swap"
        rel="stylesheet"
      />
      <style>
        :root {
          --bg-gradient: linear-gradient(135deg, #4c76e2, #49d295);
          --error-color: #ff4f4f;
          --success-color: #49d295;
        }
        body {
          font-family: 'Poppins', sans-serif;
          background: var(--bg-gradient);
          height: 100vh;
          margin: 0;
          display: flex;
          justify-content: center;
          align-items: center;
          position: relative;
        }
        .forgot-container {
          background: rgba(255, 255, 255, 0.2);
          backdrop-filter: blur(10px);
          border-radius: 10px;
          padding: 2rem;
          width: 360px;
          text-align: center;
          box-shadow: 0 8px 20px rgba(0,0,0,0.2);
          animation: fadeInDown 0.5s ease forwards;
        }
        @keyframes fadeInDown {
          from {
            opacity: 0;
            transform: translateY(-30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        h2 {
          margin-bottom: 1.5rem;
          color: #fff;
        }
        form {
          display: flex;
          flex-direction: column;
        }
        input[type="email"] {
          padding: 0.8rem;
          margin-bottom: 1rem;
          border: 1px solid #fff;
          border-radius: 6px;
          font-size: 1rem;
          background: rgba(255, 255, 255, 0.7);
          color: #333;
        }
        button {
          padding: 0.8rem;
          background: #4c76e2;
          border: none;
          border-radius: 6px;
          color: #fff;
          font-size: 1rem;
          cursor: pointer;
          transition: background 0.3s;
        }
        button:hover {
          background: #49d295;
        }
        a {
          display: block;
          margin-top: 1rem;
          color: #fff;
          text-decoration: none;
          font-weight: 500;
        }
        a:hover {
          text-decoration: underline;
        }
        #message {
          display: none;
          margin-bottom: 1rem;
          font-weight: bold;
        }
      </style>
    </head>
    <body>
      <div class="forgot-container">
        <h2>Recuperar Contraseña</h2>
        <div id="message"></div>
        <form action="/forgot-password" method="POST">
          <input type="email" name="email" placeholder="Introduce tu correo" required />
          <button type="submit">Enviar enlace de reinicio</button>
        </form>
        <a href="/">Volver</a>
      </div>

      <script>
        window.addEventListener('DOMContentLoaded', () => {
          const params = new URLSearchParams(window.location.search);
          const messageDiv = document.getElementById('message');
          if (params.has('error')) {
            const errCode = params.get('error');
            messageDiv.textContent = getErrorText(errCode);
            messageDiv.style.color = 'red';
            messageDiv.style.display = 'block';
          }
          if (params.get('success') === 'true') {
            messageDiv.textContent = "¡Enlace de reinicio enviado! Revisa tu correo.";
            messageDiv.style.color = 'limegreen';
            messageDiv.style.display = 'block';
          }
        });
        function getErrorText(code) {
          switch (code) {
            case 'notfound':
              return 'Si el correo existe, se enviará el enlace de reinicio.';
            case 'tokenfail':
              return 'Ocurrió un problema al generar el token.';
            case 'savefail':
              return 'No se pudo guardar la información. Intenta de nuevo.';
            case 'sendfail':
              return 'No se pudo enviar el correo. Intenta más tarde.';
            default:
              return 'Ha ocurrido un error desconocido.';
          }
        }
      </script>
    </body>
    </html>
  `);
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err || !user) {
      return res.redirect('/forgot-password?error=notfound');
    }
    crypto.randomBytes(20, (err, buffer) => {
      if (err) {
        return res.redirect('/forgot-password?error=tokenfail');
      }
      const token = buffer.toString('hex');
      const expiration = Date.now() + 3600000; 
      db.run(
        "UPDATE users SET resetToken = ?, resetTokenExpiration = ? WHERE email = ?",
        [token, expiration, email],
        (err) => {
          if (err) {
            return res.redirect('/forgot-password?error=savefail');
          }
          const resetLink = `http://localhost:3000/reset-password?token=${token}`;
          const mailOptions = {
            from: 'TU CORREO',
            to: email,
            subject: 'Reinicio de contraseña',
            html: `
              <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
              <a href="${resetLink}">${resetLink}</a>
              <p>El enlace expirará en 1 hora.</p>
            `
          };
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error(error);
              return res.redirect('/forgot-password?error=sendfail');
            }
            return res.redirect('/forgot-password?success=true');
          });
        }
      );
    });
  });
});

app.get('/reset-password', (req, res) => {
  const { token } = req.query;
  db.get(
    "SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiration > ?",
    [token, Date.now()],
    (err, user) => {
      if (err || !user) {
        return res.send("El enlace es inválido o ha expirado. <a href='/'>Volver</a>");
      }
      res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Restablecer Contraseña</title>
          <link
            href="https://fonts.googleapis.com/css?family=Poppins:300,400,500,600&display=swap"
            rel="stylesheet"
          />
          <style>
            body {
              background: var(--bg-gradient, linear-gradient(135deg, #4c76e2, #49d295));
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              margin: 0;
              font-family: 'Poppins', sans-serif;
            }
            .reset-container {
              background: rgba(255,255,255,0.2);
              backdrop-filter: blur(10px);
              padding: 2rem;
              border-radius: 10px;
              width: 360px;
              text-align: center;
              color: #fff;
              box-shadow: 0 8px 20px rgba(0,0,0,0.2);
              animation: fadeInDown 0.5s ease forwards;
            }
            @keyframes fadeInDown {
              from {
                opacity: 0;
                transform: translateY(-30px);
              }
              to {
                opacity: 1;
                transform: translateY(0);
              }
            }
            h2 {
              margin-bottom: 1rem;
            }
            form {
              display: flex;
              flex-direction: column;
            }
            input[type="password"] {
              padding: 0.8rem;
              margin-bottom: 1rem;
              border: 1px solid #fff;
              border-radius: 6px;
              font-size: 1rem;
              background: rgba(255, 255, 255, 0.7);
              color: #333;
            }
            button {
              padding: 0.8rem;
              background: #4c76e2;
              border: none;
              border-radius: 6px;
              color: #fff;
              font-size: 1rem;
              cursor: pointer;
              transition: background 0.3s;
            }
            button:hover {
              background: #49d295;
            }
            a {
              display: block;
              margin-top: 1rem;
              color: #fff;
              text-decoration: none;
              font-weight: 500;
            }
            a:hover {
              text-decoration: underline;
            }
          </style>
        </head>
        <body>
          <div class="reset-container">
            <h2>Restablecer Contraseña</h2>
            <form action="/reset-password" method="POST">
              <input type="hidden" name="token" value="${token}" />
              <input
                type="password"
                name="password"
                placeholder="Nueva contraseña"
                required
              />
              <input
                type="password"
                name="confirm_password"
                placeholder="Confirmar contraseña"
                required
              />
              <button type="submit">Restablecer</button>
            </form>
            <a href="/">Volver</a>
          </div>
        </body>
        </html>
      `);
    }
  );
});

app.post('/reset-password', (req, res) => {
  const { token, password, confirm_password } = req.body;
  if (password !== confirm_password) {
    return res.send("Las contraseñas no coinciden. <a href='/'>Volver</a>");
  }
  db.get(
    "SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiration > ?",
    [token, Date.now()],
    (err, user) => {
      if (err || !user) {
        return res.send("El enlace es inválido o ha expirado. <a href='/'>Volver</a>");
      }
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.send("Error al encriptar la contraseña.");
        db.run(
          "UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiration = NULL WHERE id = ?",
          [hashedPassword, user.id],
          (err) => {
            if (err) return res.send("Error al actualizar la contraseña.");
            res.send("Contraseña restablecida con éxito. <a href='/'>Inicia sesión</a>");
          }
        );
      });
    }
  );
});

app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000");
});
