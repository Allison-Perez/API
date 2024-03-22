const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const port = process.env.port || 5000;

app.use(cors());
app.use(bodyParser.json());

const dbConfig = {
  host: "82.180.153.103",
  user: "u214519598_acanner",
  password: "111019As",
  database: "u214519598_acanner",
}


function generarContrasenaTemporal() {
  const longitud = 12;
  return crypto.randomBytes(Math.ceil(longitud / 2))
    .toString('hex')
    .slice(0, longitud);
}

// LOGEO

app.post("/login", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const { correo, password } = req.body;

    // Consultar al usuario en la base de datos por correo
    const [rows] = await connection.execute("SELECT * FROM usuario WHERE correo = ?", [correo]);
    if (rows.length === 0) {
      return res.status(401).json({ message: "Correo o contraseña incorrectos" });
    }

    const usuario = rows[0];


    const match = await bcrypt.compare(password, usuario.password);
    if (!match) {
      return res.status(401).json({ message: "Correo o contraseña incorrectos" });
    }

    // Cerrar la conexión y enviar la respuesta
    connection.end();
    res.status(200).json({ message: "Inicio de sesión exitoso" });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);
    res.status(500).json({ error: "Error en el inicio de sesión" });
  }
});

// REGISTRO

app.post("/registro", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);

    const {
      primer_nombre,
      primer_apellido,
      tipo_documento,
      fecha_nacimiento,
      correo,
      segundo_nombre,
      segundo_apellido,
      id_usuario,
      ficha,
      password,
      pregunta_seguridad,
      respuesta_seguridad,
    } = req.body;

    const passwordEncriptado = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO usuario (primer_nombre, primer_apellido, tipo_documento, fecha_nacimiento, correo, segundo_nombre, segundo_apellido, id_usuario, ficha, password, pregunta_seguridad, respuesta_seguridad, rol)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    await connection.execute(sql, [
      primer_nombre,
      primer_apellido,
      tipo_documento,
      fecha_nacimiento,
      correo,
      segundo_nombre,
      segundo_apellido,
      id_usuario,
      ficha,
      passwordEncriptado,
      pregunta_seguridad,
      respuesta_seguridad,
      2
    ]);

    connection.end();
    res.status(201).json({ message: "Usuario creado exitosamente" });
  } catch (error) {
    console.error("Error al insertar el registro:", error);
    res.status(500).json({ error: "Error al insertar el registro" });
  }
});


// RECUPERAR CORREO (VERIFICANDO SI EXISTE)

app.post("/recuperar", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const { correo } = req.body;

    const [rows] = await connection.execute("SELECT * FROM usuario WHERE correo = ?", [correo]);

    if (rows.length === 0) {
      return res.status(404).json({ message: "Correo no encontrado en la base de datos" });
    }

    connection.end();
    res.status(200).json({ message: "Correo de recuperación enviado" });
  } catch (error) {
    console.error("Error en la recuperación de contraseña:", error);
    res.status(500).json({ error: "Error en la recuperación de contraseña" });
  }
});

// TRAE LA PREGUNTA DE SEGURIDAD


app.get('/api/preguntaSeguridad/:correo', async (req, res) => {
  const correo = req.params.correo;

  console.log(correo);

  try {
    const connection = await mysql.createConnection(dbConfig);

    const sql = `
      SELECT u.pregunta_seguridad, p.descripcionP
      FROM usuario u
      LEFT JOIN preguntaseguridad p ON u.pregunta_seguridad = p.id_pregunta
      WHERE u.correo = ?`;

    const [rows] = await connection.execute(sql, [correo]);

    await connection.end();

    if (rows.length > 0) {
      const preguntaSeguridad = rows[0].pregunta_seguridad;
      const descripcionP = rows[0].descripcionP;
      res.json({ pregunta: preguntaSeguridad, descripcion: descripcionP });
    } else {
      res.status(404).json({ mensaje: 'Correo no encontrado' });
    }
  } catch (error) {
    console.error('Error al consultar la pregunta de seguridad:', error);
    res.status(500).json({ mensaje: 'Error al consultar la pregunta de seguridad' });
  }
});


// VERIFICA LA RESPUESTA DE SEGURIDAD Y ASIGNACIÓN DE CONTRASEÑA TEMPORAL

app.post('/api/verificarRespuesta', async (req, res) => {
  try {
    const { correo, respuesta } = req.body;
    console.log('Correo recibido:', correo);
    console.log('Respuesta recibida:', respuesta);

    const connection = await mysql.createConnection(dbConfig);

    const consultaSQL = "SELECT respuesta_seguridad FROM usuario WHERE correo = ?";

    const [rows] = await connection.execute(consultaSQL, [correo]);

    if (rows.length > 0) {
      const respuestaCorrecta = rows[0].respuesta_seguridad;
      if (respuesta === respuestaCorrecta) {

        const nuevaContrasenaTemporal = generarContrasenaTemporal();
        const passwordEncriptado = await bcrypt.hash(nuevaContrasenaTemporal, 10);

        const actualizacionSQL = "UPDATE usuario SET password = ? WHERE correo = ?";
        const [result] = await connection.execute(actualizacionSQL, [passwordEncriptado, correo]);

        if (result.affectedRows === 1) {
          // Actualización exitosa
          res.json({ esValido: true, contrasenaTemporal: nuevaContrasenaTemporal });
        } else {
          // No se actualizó ninguna fila (posible problema en la consulta SQL)
          res.status(500).json({ error: "Error al actualizar la contraseña temporal" });
        }

      } else {
        // Respuesta incorrecta
        res.json({ esValido: false });
      }
    } else {
      // Correo no encontrado
      res.status(404).json({ mensaje: 'Correo no encontrado' });
    }

    connection.end();
  } catch (error) {
    console.error('Error al verificar la respuesta:', error);
    res.status(500).json({ error: "Error al verificar la respuesta" });
  }
});


// MOSTRAR INFORMACIÓN EN EL PERFIL

app.get('/api/obtener-usuario', async (req, res) => {
  const correo = req.query.correo;
  console.log(correo);
  const sql = `SELECT primer_nombre, segundo_nombre, primer_apellido, segundo_apellido, ficha, correo, password FROM usuario WHERE correo = ?`;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(sql, [correo]);

    await connection.end();

    if (rows.length === 1) {
      const usuario = rows[0];
      res.json(usuario);
    } else {
      res.status(404).json({ error: 'Usuario no encontrado' });
    }
  } catch (error) {
    console.error('Error al obtener el usuario: ' + error);
    res.status(500).json({ error: 'Error al obtener el usuario' });
  }
});


// EDITAR LA INFORMACIÓN DEL PERFIL


app.post('/api/actualizar-usuario', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const { correo } = req.query;
    const userData = req.body;

    if (!userData.primerNombre || !userData.segundoNombre || !userData.primerApellido) {
      return res.status(400).json({ error: 'Campos obligatorios faltantes' });
    }

    // Realiza la actualización en la base de datos utilizando el correo
    const updateSql = `
      UPDATE usuario
      SET
        primer_nombre = ?,
        segundo_nombre = ?,
        primer_apellido = ?,
        segundo_apellido = ?
      WHERE correo = ?`; // Eliminado "ficha" de la consulta SQL
    const { primerNombre, segundoNombre, primerApellido, segundoApellido } = userData;
    const values = [primerNombre, segundoNombre, primerApellido, segundoApellido, correo];

    await connection.execute(updateSql, values);

    // Cerrar la conexión y enviar la respuesta
    connection.end();
    res.status(200).json({ message: 'Los cambios se guardaron correctamente' });
  } catch (error) {
    console.error('Error al actualizar la información del usuario:', error);
    res.status(500).json({ error: 'Error al actualizar la información del usuario' });
  }
});


// CAMBIAR LA CONTRASEÑA ESTANDO LOGEADO


app.post("/api/cambiar-contrasena", async (req, res) => {
  try {
    const { correo, passwordAnterior, nuevaPassword } = req.body;
    const connection = await mysql.createConnection(dbConfig);

    // Consultar al usuario en la base de datos por correo
    const [rows] = await connection.execute("SELECT * FROM usuario WHERE correo = ?", [correo]);
    if (rows.length === 0) {
      return res.status(401).json({ message: "Usuario no encontrado" });
    }

    const usuario = rows[0];

    // Verificar la contraseña anterior
    const match = await bcrypt.compare(passwordAnterior, usuario.password);
    if (!match) {
      return res.status(401).json({ message: "La contraseña anterior es incorrecta" });
    }

    // Encriptar la nueva contraseña temporal
    const passwordEncriptado = await bcrypt.hash(nuevaPassword, 10);

    // Actualizar la contraseña en la base de datos
    const updateSql = "UPDATE usuario SET password = ? WHERE correo = ?";
    await connection.execute(updateSql, [passwordEncriptado, correo]);

    // Cerrar la conexión y enviar la respuesta
    connection.end();
    res.status(200).json({ message: "Contraseña cambiada con éxito", nuevaPassword });
  } catch (error) {
    console.error("Error al cambiar la contraseña:", error);
    res.status(500).json({ error: "Error al cambiar la contraseña" });
  }
});



app.listen(port, () => {
  console.log(`Servidor en ejecución en http://localhost:${port}`);
});
