const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const path = require('path');
const { log } = require("console");
const app = express();
const port = 3306;

app.use(cors());
app.use(bodyParser.json());

const dbConfig = {
  host: "82.180.153.103",
  user: "u214519598_acanner",
  port:"3306",
  password: "111019As",
  database: "u214519598_acanner",
};

function generarContrasenaTemporal() {
  const longitud = 12;
  return crypto.randomBytes(Math.ceil(longitud / 2))
    .toString('hex')
    .slice(0, longitud);
}

// REGISTRO

app.post("/registro", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);

    console.log("Datos del cuerpo de la solicitud:", req.body);


    const {
      primerNombre,
      primerApellido,
      tipoDocumento,
      fechaNacimiento,
      correo,
      segundoNombre,
      segundoApellido,
      documento,
      ficha,
      password,
      idPregunta,
      respuestaPregunta,
    } = req.body;

    const passwordEncriptado = await bcrypt.hash(password, 10);
    console.log("Contraseña encriptada:", passwordEncriptado);


    const sql = `INSERT INTO usuario (primerNombre , primerApellido, tipoDocumento, fechaNacimiento, correo, segundoNombre, segundoApellido, documento, password, idPregunta, respuestaPregunta, idRol, fotoPerfil )
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)`;

    await connection.execute(sql, [
      primerNombre ,
      primerApellido ,
      tipoDocumento ,
      fechaNacimiento ,
      correo,
      segundoNombre ,
      segundoApellido ,
      documento ,
      passwordEncriptado,
      idPregunta,
      respuestaPregunta,
      2,
      'http://localhost:3000/uploads/sena.png',
    ]);

    console.log("Usuario creado exitosamente");

    const [lastInsertRow] = await connection.execute("SELECT LAST_INSERT_ID() as lastId");
    const idUsuario = lastInsertRow[0].lastId;

    await connection.execute("INSERT INTO usuarioFicha (idUsuario, idFicha) VALUES (?, ?)", [idUsuario, ficha]);
    console.log("Usuario y ficha registrados exitosamente");


    connection.end();
    res.status(201).json({ message: "Usuario creado exitosamente" });
  } catch (error) {
    console.error("Error al insertar el registro:", error);
    res.status(500).json({ error: "Error al insertar el registro" });
  }
});

// LOGEO
app.post("/login", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const { correo, password } = req.body;

    const [rows] = await connection.execute("SELECT * FROM usuario WHERE correo = ?", [correo]);
    if (rows.length === 0) {
      return res.status(401).json({ message: "Correo o contraseña incorrectos" });
    }

    const usuario = rows[0];

    const match = await bcrypt.compare(password, usuario.password);
    if (!match) {
      return res.status(401).json({ message: "Correo o contraseña incorrectos" });
    }

    const userInfo = {
      idUsuario: usuario.identificador,
      primerNombre: usuario.primerNombre,
      segundoNombre: usuario.segundoNombre,
      primerApellido: usuario.primerApellido,
      segundoApellido: usuario.segundoApellido,
      correo: usuario.correo,
    };

    // Obtener las fichas asociadas al usuario
    const [fichas] = await connection.execute("SELECT idFicha FROM usuarioFicha WHERE idUsuario = ?", [usuario.identificador]);
    const fichasUsuario = fichas.map(ficha => ficha.idFicha);

    // Generar el token con todas las fichas asignadas
    const token = jwt.sign({ idUsuario: usuario.identificador, fichas: fichasUsuario, correo: usuario.correo }, 'acanner', { expiresIn: '1h' });

    // Cerrar la conexión y enviar la respuesta con el token
    connection.end();
    res.status(200).json({ message: "Inicio de sesión exitoso", idRol: usuario.idRol, userInfo: userInfo, fichas: fichasUsuario, token: token });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);
    res.status(500).json({ error: "Error en el inicio de sesión" });
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
    res.status(200).json({ message: "El correo se encuentra registrado en la base de datos" });
  } catch (error) {
    console.error("No se ha podido encontrar el correo ingresado", error);
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
      SELECT u.idPregunta, p.pregunta
      FROM usuario u
      LEFT JOIN preguntaSeguridad p ON u.idPregunta = p.identificador
      WHERE u.correo = ?`;

    const [rows] = await connection.execute(sql, [correo]);

    await connection.end();

    if (rows.length > 0) {
      const preguntaSeguridad = rows[0].idPregunta;
      const pregunta = rows[0].pregunta;
      res.json({ idPregunta: preguntaSeguridad, pregunta: pregunta });
    } else {
      res.status(404).json({ mensaje: 'Correo no encontrado' });
    }
  } catch (error) {
    console.error('Error al consultar la pregunta de seguridad:', error);
    res.status(500).json({ mensaje: 'Error al consultar la pregunta de seguridad' });
  }
});

// VERIFICA RESPUESTA Y MANDA CONTRASEÑA TEMPORAL

app.post('/api/verificarRespuesta', async (req, res) => {
  try {
    const { correo, respuesta } = req.body;
    console.log('Correo recibido:', correo);
    console.log('Respuesta recibida:', respuesta);

    const connection = await mysql.createConnection(dbConfig);

    const consultaSQL = "SELECT respuestaPregunta FROM usuario WHERE correo = ?";

    const [rows] = await connection.execute(consultaSQL, [correo]);

    if (rows.length > 0) {
      const respuestaCorrecta = rows[0].respuestaPregunta;
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

// MOSTRAR INFORMACIÓN EN EL PERFIL ADMIN

app.get('/api/obtener-usuario', async (req, res) => {
  const correo = req.query.correo;
  console.log(correo);
  const sql = `SELECT primerNombre, segundoNombre, primerApellido, segundoApellido, correo, password FROM usuario WHERE correo = ?`;

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

// Obtener un usuario por correo electrónico 
app.get("/api/obtenerUsuario", async (req, res) => {
  try {
    const { correo } = req.query;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `SELECT * FROM usuario WHERE correo = ?`;
    const [rows] = await connection.execute(sql, [correo]);

    connection.end();
    if (rows.length > 0) {
      res.status(200).json(rows[0]);
    } else {
      res.status(404).json({ error: "Usuario no encontrado" });
    }
  } catch (error) {
    console.error("Error al obtener el usuario por correo:", error);
    res.status(500).json({ error: "Error al obtener el usuario por correo" });
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

    const updateSql = `
      UPDATE usuario
      SET
        primerNombre = ?,
        segundoNombre = ?,
        primerApellido = ?,
        segundoApellido = ?
      WHERE correo = ?`; 
    const { primerNombre, segundoNombre, primerApellido, segundoApellido } = userData;
    const values = [primerNombre, segundoNombre, primerApellido, segundoApellido, correo];

    await connection.execute(updateSql, values);


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


// ADMIN LISTA USUARIOS

app.get("/api/usuarios", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(`
      SELECT
        u.identificador,
        u.documento,
        u.primerNombre,
        u.primerApellido,
        f.numeroFicha,
        u.correo,
        r.nombre as rol
      FROM
        usuario u
      JOIN
        usuarioFicha uf ON u.identificador = uf.idUsuario
      JOIN
        ficha f ON uf.idFicha = f.identificador
      JOIN
        rol r ON u.idRol = r.identificador
    `);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener usuarios:", error);
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

// FUNCIÓN PARA REALIZAR UN INSERT A LA TABLA DETALLE USUARIO SOLO SI EL USUARIO NO EXISTE

async function insertarDetalleUsuarioPredeterminado(correo) {
  try {
    const connection = await mysql.createConnection(dbConfig);

    const esInstructorQuery = `
      SELECT idRol FROM usuario
      WHERE correo = ?`;

    const [esInstructorResult] = await connection.execute(esInstructorQuery, [correo]);

    if (esInstructorResult[0].idRol === 1) {
      const existeRegistroQuery = `
        SELECT COUNT(*) AS count
        FROM detalleusuario
        WHERE idUsuario = (SELECT identificador FROM usuario WHERE correo = ? AND idRol = 1)`;

      const [existeRegistroResult] = await connection.execute(existeRegistroQuery, [correo]);

      if (existeRegistroResult[0].count === 0) {
        // Inserta en detalleusuario con datos predeterminados
        const insertDetalleUsuarioQuery = `
          INSERT INTO detalleusuario (fechaIngreso, celular, informacionAcademica, informacionAdicional, idUsuario)
          VALUES (?, ?, ?, ?, (SELECT identificador FROM usuario WHERE correo = ? AND idRol = 1))`;

        const fechaIngresoPredeterminada = '2022-01-01';
        const celularPredeterminado = '123456789';
        const informacionAcademicaPredeterminada = 'Sin información académica';
        const informacionAdicionalPredeterminada = 'Sin información adicional';

        await connection.execute(insertDetalleUsuarioQuery, [
          fechaIngresoPredeterminada,
          celularPredeterminado,
          informacionAcademicaPredeterminada,
          informacionAdicionalPredeterminada,
          correo
        ]);
      }
    }
    else{
      const eliminarDetalleUsuarioQuery = `
        DELETE FROM detalleusuario
        WHERE idUsuario = (SELECT identificador FROM usuario WHERE correo = ?)`;

      await connection.execute(eliminarDetalleUsuarioQuery, [correo]);
    }

    connection.end();
  } catch (error) {
    console.error("Error al insertar en detalleusuario con datos predeterminados:", error);
  }
}

// ADMIN MODIFICA USUARIOS

app.post('/api/modificar-usuarios', async (req, res) => {
  try {
    // Asegúrate de que req.body y req.body.email estén definidos
    if (!req.body || !req.body.email) {
      return res.status(400).json({ error: 'Correo electrónico no proporcionado en la solicitud' });
    }

    const connection = await mysql.createConnection(dbConfig);
    const userEmail = req.body.email;
    const userData = req.body.updatedUser;

    console.log('Datos del usuario a actualizar:', userData);

    // Verificar si el usuario existe
    const [userIdResult] = await connection.execute('SELECT identificador FROM usuario WHERE correo = ?', [userEmail]);

    if (userIdResult.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const userId = userIdResult[0].identificador;

    const [fichaExists] = await connection.execute('SELECT * FROM ficha WHERE identificador = ?', [userData.numeroFicha]);

    if (fichaExists.length === 0) {
      return res.status(404).json({ error: 'Ficha no encontrada' });
    }

    const updateSql = `
      UPDATE usuario
      SET
        primerNombre = ?,
        primerApellido = ?,
        idRol = ?
      WHERE correo = ?`;

    const values = [
      userData.primerNombre,
      userData.primerApellido,
      userData.rol,
      userEmail
    ];

    const updateFichaSql = `
    UPDATE usuarioFicha
    SET idFicha = ?
    WHERE idUsuario = ?`;
  
  const fichaValues = [
    userData.numeroFicha,
    userId
  ];

    console.log('Consulta SQL (Usuario):', updateSql);
    console.log('Valores (Usuario):', values);

    console.log('Consulta SQL (Ficha):', updateFichaSql);
    console.log('Valores (Ficha):', fichaValues);

    await connection.execute(updateSql, values);
    await connection.execute(updateFichaSql, fichaValues);

    // INSERTA A LA TABLA DETALLE USUARIO

    await insertarDetalleUsuarioPredeterminado(userEmail);
    
    connection.end();
    res.status(200).json({ message: 'Los cambios se guardaron correctamente' });
  } catch (error) {
    console.error('Error al actualizar el usuario:', error);
    res.status(500).json({ error: 'Error interno en el servidor' });
  }
});


// LISTADO DE INSTRUCTORES EN ADMIN

app.get('/api/staticsinstructores', async (req, res) => {
  const sql = `
  SELECT
  u.documento,
  u.primerNombre,
  u.segundoNombre,
  u.primerApellido,
  u.segundoApellido,
  u.fechaNacimiento,
  f.numeroFicha,
  u.correo,
  du.celular,
  du.fechaIngreso
FROM
  usuario u
JOIN usuarioFicha uf ON u.identificador = uf.idUsuario
JOIN ficha f ON uf.idFicha = f.identificador
JOIN detalleusuario du ON u.identificador = du.idUsuario;
`
  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(sql);

    await connection.end();

    if (rows.length > 0) {
      res.json(rows);
    } else {
      res.status(404).json({ error: 'Usuarios no encontrados' });
    }
  } catch (error) {
    console.error('Error al obtener los usuarios: ' + error);
    res.status(500).json({ error: 'Error al obtener los usuarios' });
  }
});

// ADMIN ASIGNA FICHAS

// Lista las fichas

app.get('/api/fichas', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute('SELECT * FROM ficha');
    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener la lista de fichas:', error);
    res.status(500).json({ error: 'Error al obtener la lista de fichas' });
  }
});

// Lista a los instructores

app.get('/api/instructores', async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute('SELECT identificador, primerNombre, primerApellido FROM usuario WHERE idRol = 1');
    connection.end();
    res.json(rows);
  } catch (error) {
    console.error('Error al obtener la lista de instructores:', error);
    res.status(500).json({ error: 'Error al obtener la lista de instructores' });
  }
});


// Agregar ficha a un instructor
app.post('/api/asignar-ficha', async (req, res) => {
  try {
    const { idUsuario, idFicha } = req.body;
    console.log(idUsuario, idFicha );
    if (!idUsuario || !idFicha) {
      return res.status(400).json({ error: 'Se requieren idUsuario e idFicha' });
    }

    const connection = await mysql.createConnection(dbConfig);
    const [existingRecord] = await connection.execute(
      'SELECT * FROM usuarioFicha WHERE idUsuario = ? AND idFicha = ?',
      [idUsuario, idFicha]
    );

    if (existingRecord.length > 0) {
      return res.status(400).json({ error: 'Ya existe un registro para este usuario y ficha' });
    }

    const result = await connection.execute('INSERT INTO usuarioFicha (idUsuario, idFicha) VALUES (?, ?)', [idUsuario, idFicha]);
    connection.end();

    res.status(200).json({ message: 'Ficha asignada correctamente' });

  } catch (error) {
    console.error('Error al asignar la ficha al usuario:', error);
    res.status(500).json({ error: 'Error al asignar la ficha al usuario' });
  }
});


// DONA INSTRUCTORES FICHAS

app.get('/api/fichasInstructores', async (req, res) => {
  const sql = `
    SELECT
      f.numeroFicha,
      COUNT(u.idRol) as totalInstructores,
      COUNT(u.idRol) / (SELECT COUNT(*) FROM usuario WHERE idRol = 1) * 100 as porcentajeInstructores
    FROM
      usuario u
    JOIN usuarioFicha uf ON u.identificador = uf.idUsuario
    JOIN ficha f ON uf.idFicha = f.identificador
    WHERE u.idRol = 1
    GROUP BY f.numeroFicha;
  `;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(sql);
    await connection.end();

    if (rows.length > 0) {
      res.json(rows);
    } else {
      res.status(404).json({ error: 'Datos de instructores no encontrados' });
    }
  } catch (error) {
    console.error('Error al obtener datos de instructores: ' + error);
    res.status(500).json({ error: 'Error al obtener datos de instructores' });
  }
});


// ESTADISTICAS ANTIGUEDAD

app.get('/api/antiguedadInstructores', async (req, res) => {
  const sql = `
    SELECT U.identificador AS ID_Instructor, U.primerNombre, U.primerApellido,
             DATEDIFF(CURDATE(), DU.fechaIngreso) AS Antiguedad_Dias
    FROM usuario U
    JOIN detalleusuario DU ON U.identificador = DU.idUsuario
    WHERE U.idRol = 1
    ORDER BY Antiguedad_Dias DESC;
  `;

  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(sql);

    await connection.end();

    if (rows.length > 0) {
      res.json({ rows });
    } else {
      res.status(404).json({ error: 'Datos de instructores no encontrados' });
    }
  } catch (error) {
    console.error('Error al obtener datos de instructores: ' + error);
    res.status(500).json({ error: 'Error al obtener datos de instructores' });
  }
});


// ESTADISTICAS CANTIDAD DE BLOGS

app.get("/api/blogsPorInstructor", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(`
      SELECT
        u.identificador AS idInstructor,
        u.primerNombre AS nombreInstructor,
        COUNT(b.identificador) AS cantidadBlogsSubidos
      FROM
        usuario u
      JOIN
        blog b ON u.identificador = b.idUsuario
      WHERE
        u.idRol = 1
      GROUP BY
        u.identificador, u.primerNombre
    `);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener la cantidad de blogs por instructor:", error);
    res.status(500).json({ error: "Error al obtener la cantidad de blogs por instructor" });
  }
});

// ESTADISTICAS POR GUIAS

app.get("/api/guiasPorInstructor", async (req, res) => {
  console.log('entra AL NUEVO GRAFICO');
  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(`
      SELECT
      u.identificador AS idInstructor,
      u.primerNombre AS nombreInstructor,
      COUNT(g.identificador) AS cantidadGuiasSubidas
      FROM
        usuario u
      JOIN
        guias g ON u.identificador = g.idUsuario
      WHERE
        u.idRol = 1
      GROUP BY
        u.identificador, u.primerNombre
    `);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener la cantidad de blogs por instructor:", error);
    res.status(500).json({ error: "Error al obtener la cantidad de blogs por instructor" });
  }
});

// DONA APRENDICES

app.get('/api/fichasAprendices', async (req, res) => {
  const sql = `
    SELECT
      f.numeroFicha,
      COUNT(u.idRol) as totalAprendices,
      COUNT(u.idRol) / (SELECT COUNT(*) FROM usuario WHERE idRol = 2) * 100 as porcentajeAprendices
    FROM
      usuario u
    JOIN usuarioFicha uf ON u.identificador = uf.idUsuario
    JOIN ficha f ON uf.idFicha = f.identificador
    WHERE u.idRol = 2
    GROUP BY f.numeroFicha;
  `;

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(sql);
    await connection.end();

    if (rows.length > 0) {
      res.json(rows);
    } else {
      res.status(404).json({ error: 'Datos de instructores no encontrados' });
    }
  } catch (error) {
    console.error('Error al obtener datos de instructores: ' + error);
    res.status(500).json({ error: 'Error al obtener datos de instructores' });
  }
});

// ESTADISTICAS EDADES

app.get("/api/promedioEdades", async (req, res) => {
  try {
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(`
      SELECT
        CASE
          WHEN YEAR(CURDATE()) - YEAR(u.fechaNacimiento) BETWEEN 14 AND 18 THEN '14-18'
          WHEN YEAR(CURDATE()) - YEAR(u.fechaNacimiento) BETWEEN 18 AND 25 THEN '18-25'
          WHEN YEAR(CURDATE()) - YEAR(u.fechaNacimiento) BETWEEN 26 AND 35 THEN '26-35'
          WHEN YEAR(CURDATE()) - YEAR(u.fechaNacimiento) BETWEEN 36 AND 45 THEN '36-45'
          ELSE '46+'
        END as rango_edad,
        COUNT(*) as cantidad
      FROM usuario u
      WHERE u.idRol = 2
      GROUP BY rango_edad
    `);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener la distribución de edades:", error);
    res.status(500).json({ error: "Error al obtener la distribución de edades" });
  }
});


// ESTADISTICAS POR FICHAS

app.get('/api/asistenciaFichas', async (req, res) => {
  console.log('asitencia entra');
  try {
    const connection = await mysql.createConnection(dbConfig);

    const sql = `
    SELECT f.numeroFicha, 
    COUNT(*) AS total_sesiones,
    SUM(CASE WHEN a.status = 'Asistió' THEN 1 ELSE 0 END) AS sesiones_asistidas,
    AVG(CASE WHEN a.status = 'Asistió' THEN 1 ELSE 0 END) * 100 AS porcentaje_asistencia
FROM asistencia a
LEFT JOIN ficha f ON a.idFicha = f.identificador
GROUP BY f.numeroFicha
      `;

    const [rows] = await connection.execute(sql);

    await connection.end();

    res.json(rows); // Devolver los datos de asistencia
  } catch (error) {
    console.error('Error al obtener los datos de asistencia:', error);
    res.status(500).json({ error: 'Error al obtener los datos de asistencia' });
  }
});

//MARLON

// OBTENER INFORMACIÓN DEL PERFIL

app.get("/api/obtenerInstructor", async (req, res) => {
  try {

    const { correo } = req.query;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `
      SELECT
        u.documento,
        u.primerNombre,
        u.segundoNombre,
        u.primerApellido,
        u.segundoApellido,
        u.fechaNacimiento,
        f.numeroFicha,
        u.correo,
        du.celular,
        du.fechaIngreso,
        du.informacionAcademica,
        du.informacionAdicional
      FROM
        usuario u
        JOIN usuarioFicha uf ON u.identificador = uf.idUsuario
        JOIN ficha f ON uf.idFicha = f.identificador
        JOIN detalleusuario du ON u.identificador = du.idUsuario
        WHERE u.idRol = 1 AND u.correo = ?
    `;
    const [rows] = await connection.execute(sql, [correo]);

    connection.end();
    if (rows.length > 0) {
      res.status(200).json(rows[0]);
    } else {
      res.status(404).json({ error: "Usuario no encontrado" });
    }
  } catch (error) {
    console.error("Error al obtener el usuario por correo:", error);
    res.status(500).json({ error: "Error al obtener el usuario por correo" });
  }
});

// EDITAR LA INFORMACIÓN DEL INSTRUCTOR

app.put("/api/actualizarInstructor", async (req, res) => {
  let connection;
  try {
    const { correo } = req.query;
    const userData = req.body;

    if (!userData.primerNombre || !userData.primerApellido || !userData.fechaIngreso || !userData.celular ) {
      return res.status(400).json({ error: 'Todos los campos obligatorios son necesarios' });
    }
    connection = await mysql.createConnection(dbConfig);

    // Actualiza la información en la tabla 'usuario'
    const updateUsuarioSql = `
      UPDATE usuario
      SET
        primerNombre = ?,
        segundoNombre = ?,
        primerApellido = ?,
        segundoApellido = ?
      WHERE correo = ?`;

    const { primerNombre, segundoNombre, primerApellido, segundoApellido } = userData;
    const usuarioValues = [primerNombre, segundoNombre, primerApellido, segundoApellido, correo];

    const [usuarioResult] = await connection.execute(updateUsuarioSql, usuarioValues);

    if (usuarioResult.affectedRows === 0) {
      return res.status(404).json({ error: "Usuario no encontrado o no es un instructor" });
    }

    const detailUser = `
    SELECT identificador FROM detalleusuario
    WHERE idUsuario = (SELECT identificador FROM usuario WHERE correo = ? AND idRol = 1)`
    const dataDatailUser = [correo]

    const resultDetailUser = await connection.execute(detailUser, dataDatailUser)

    if (resultDetailUser) {
      console.log("entra a actualizar")

      const fechaIngreso = new Date(userData.fechaIngreso);
      const fechaIngresoFormateada = fechaIngreso.toISOString().split('T')[0];
      


      const updateDetalleUsuarioSql = `
      UPDATE detalleusuario
      SET
        fechaIngreso = ?,
        celular = ?,
        informacionAcademica = ?,
        informacionAdicional = ?
      WHERE idUsuario = (SELECT identificador FROM usuario WHERE correo = ? AND idRol = 1)`;
    
      const {celular, informacionAcademica, informacionAdicional } = userData; 
      const detalleUsuarioValues = [fechaIngresoFormateada, celular, informacionAcademica, informacionAdicional, correo];


console.log(fechaIngresoFormateada);

      // Ejecuta la actualización en la tabla 'detalleUsuario'
      await connection.execute(updateDetalleUsuarioSql, detalleUsuarioValues);
    }

    // Si llega aquí, las actualizaciones fueron exitosas
    res.status(200).json({ message: 'Los cambios se guardaron correctamente' });
  } catch (error) {
    console.error("Error al editar la información del instructor:", error);
    res.status(500).json({ error: "Error al editar la información del instructor" });
  } finally {
    if (connection) {
      connection.end();
    }
  }
});


// Configuración de multer para manejar archivos adjuntos
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const extname = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + Date.now() + extname);
  }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const upload = multer({ storage: storage }); 

// Ruta para manejar la carga de archivos
app.post('/upload', upload.single('imagenOpcional'), function (req, res) {
  // Procesar la solicitud aquí
  res.send('Archivo subido exitosamente');
});

// Ruta para cambiar foto de perfil
app.post('/api/cambiar-foto', upload.single('imagen'), async (req, res) => {
  let connection;
  try {
    const { correo } = req.query;
    const nuevaImagen = req.file;

    console.log('Correo recibido:', correo);
    console.log('Imagen recibida:', nuevaImagen);

    if (!nuevaImagen) {
      console.error('No se proporcionó ninguna imagen.');
      return res.status(400).json({ error: 'No se proporcionó ninguna imagen.' });
    }

    const nuevaUrl = `http://localhost:3000/uploads/${nuevaImagen.filename}`;

    console.log('Nueva URL generada:', nuevaUrl);

    connection = await mysql.createConnection(dbConfig);

    console.log('Conexión a la base de datos exitosa.');

    const updateFotoPerfilSql = `
      UPDATE usuario
      SET fotoPerfil = ?
      WHERE correo = ?`;

    console.log('SQL de actualización:', updateFotoPerfilSql);
    console.log('Valores de actualización:', [nuevaUrl, correo]);

    await connection.execute(updateFotoPerfilSql, [nuevaUrl, correo]);

    console.log('Foto de perfil actualizada correctamente.');
    res.status(200).json({ message: 'Foto de perfil actualizada correctamente.', nuevaUrl: nuevaUrl });
  } catch (error) {
    console.error('Error al ejecutar la consulta de actualización:', error);
    res.status(500).json({ error: 'Error al cambiar la foto de perfil.' });
  }
   finally {
    if (connection) {
      connection.end();
    }
  }
});

// Ruta para obtener la foto de perfil
app.get("/api/obtener-foto-perfil", async (req, res) => {
  try {
    const { correo } = req.query;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `
      SELECT fotoPerfil
      FROM usuario
      WHERE correo = ?
    `;
    const [rows] = await connection.execute(sql, [correo]);

    connection.end();
    if (rows.length > 0) {
      res.status(200).json({ fotoPerfil: rows[0].fotoPerfil });
    } else {
      res.status(404).json({ error: "Foto de perfil no encontrada" });
    }
  } catch (error) {
    console.error("Error al obtener la foto de perfil:", error);
    res.status(500).json({ error: "Error al obtener la foto de perfil" });
  }
});

// Ruta para eliminar la foto de perfil y establecer la foto predeterminada
app.post('/api/eliminar-foto', async (req, res) => {
  let connection;
  try {
    const { correo } = req.query;

    if (!correo) {
      console.error('Correo no proporcionado.');
      return res.status(400).json({ error: 'Correo no proporcionado.' });
    }

    connection = await mysql.createConnection(dbConfig);

    const eliminarFotoPerfilSql = `
      UPDATE usuario
      SET fotoPerfil = 'assets/fotos_perfil/sena.png'
      WHERE correo = ?
    `;

    await connection.execute(eliminarFotoPerfilSql, [correo]);

    console.log('Foto de perfil eliminada y establecida como predeterminada.');
    res.status(200).json({ message: 'Foto de perfil eliminada y establecida como predeterminada.' });
  } catch (error) {
    console.error('Error al eliminar la foto de perfil:', error);
    res.status(500).json({ error: 'Error al eliminar la foto de perfil.' });
  } finally {
    if (connection) {
      connection.end();
    }
  }
});

//BLOG

// Ruta para crear un nuevo blog

app.post("/crearBlog", upload.single('imagenOpcional'), async (req, res) => {
  console.log('entra');
  try {
    const { nombre, comentario, idUsuario, idFicha } = req.body;
    let urlImagen = '';

    if (req.file) {
      urlImagen = 'http://localhost:3000/' + req.file.path;
    } else {
      urlImagen = 'http://localhost:3000/uploads/Blog.png';
    }

    const connection = await mysql.createConnection(dbConfig);
    const [fichaExists] = await connection.execute("SELECT COUNT(*) AS count FROM ficha WHERE identificador = ?", [idFicha]);
    connection.end();

    if (fichaExists[0].count === 0) {
      return res.status(400).json({ error: "La ficha seleccionada no es válida" });
    }

    if (nombre && comentario && idUsuario && idFicha) {
      const connection = await mysql.createConnection(dbConfig);
      const fechaPublicacion = new Date().toISOString()
      const fechaFormateada = fechaPublicacion.replace('T', ' ').substring(0, 19);

      const sql = `INSERT INTO blog (nombre, urlImagen, imagenOpcional, comentario, fechaPublicacion, idUsuario, idFicha)
                   VALUES (?, ?, ?, ?, ?, ?, ?)`;

      await connection.execute(sql, [nombre, urlImagen, null, comentario, fechaFormateada, idUsuario, idFicha]);
      connection.end();

      res.status(201).json({ message: "Blog creado exitosamente" });
    } else {
      res.status(400).json({ error: "Faltan campos obligatorios para crear el blog" });
    }
  } catch (error) {
    console.error("Error al crear el blog:", error);
    res.status(500).json({ error: "Error al crear el blog" });
  }
});

// Ruta para traer todos los blogs asociados al usuario

app.get("/blogsPorUsuario/:idUsuario", async (req, res) => {
  try {
    const { idUsuario } = req.params;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `SELECT * FROM blog WHERE idUsuario = ?`;
    const [rows] = await connection.execute(sql, [idUsuario]);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener los blogs por usuario:", error);
    res.status(500).json({ error: "Error al obtener los blogs por usuario" });
  }
});

// Ruta para obtener las fichas asociadas al usuario

app.get("/fichasPorUsuario/:idUsuario", async (req, res) => {
  try {
    const { idUsuario } = req.params;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `
      SELECT f.identificador, f.numeroFicha 
      FROM ficha f 
      INNER JOIN usuarioFicha uf ON f.identificador = uf.idFicha 
      WHERE uf.idUsuario = ?
    `;
    const [rows] = await connection.execute(sql, [idUsuario]);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error("Error al obtener las fichas por usuario:", error);
    res.status(500).json({ error: "Error al obtener las fichas por usuario" });
  }
});

//Editar un blog específico

app.put("/editarBlog/:idBlog", async (req, res) => {
  try {
    const { idBlog } = req.params;
    const { nombre, imagenOpcional, comentario } = req.body;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `UPDATE blog SET nombre = ?, imagenOpcional = ?, comentario = ? WHERE identificador = ?`;
    await connection.execute(sql, [nombre, imagenOpcional, comentario, idBlog]);

    connection.end();
    res.status(200).json({ message: "Blog actualizado exitosamente" });
  } catch (error) {
    console.error("Error al editar el blog:", error);
    res.status(500).json({ error: "Error al editar el blog" });
  }
});

//Eliminar noticia segun el id
app.delete("/eliminarBlog/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    
    const sql = "DELETE FROM blog WHERE identificador = ?";
    const [result] = await connection.execute(sql, [id]);

    connection.end();

    if (result.affectedRows > 0) {
      res.status(200).json({ message: "Blog eliminado correctamente" });
    } else {
      res.status(404).json({ error: "Blog no encontrado" });
    }
  } catch (error) {
    console.error("Error al eliminar el blog:", error);
    res.status(500).json({ error: "Error al eliminar el blog" });
  }
});

// HORARIOS

// Ruta para obtener horarios filtrados por identificador

app.get('/obtenerHorarios/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    
    const sql = `SELECT * FROM horario WHERE idUsuario = ?`;
    const [rows] = await connection.execute(sql, [idUsuario]);
    
    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener horarios:', error);
    res.status(500).json({ error: 'Error al obtener horarios' });
  }
});

// Ruta para obtener las fichas de un usuario
app.get('/obtenerFichas/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `SELECT identificador, numeroFicha FROM ficha WHERE idUsuario = ?`;
    const [rows] = await connection.execute(sql, [idUsuario]);

    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener las fichas:', error);
    res.status(500).json({ error: 'Error al obtener las fichas' });
  }
});

// Ruta para crear un nuevo horario
app.post('/crearHorario', upload.single('archivo'), async (req, res) => {
  try {
    const { nombre, comentario, idFicha, idUsuario } = req.body;
    let urlArchivo = '';

    if (req.file) {
      urlArchivo = '/uploads/' + req.file.filename;
    } else {
      return res.status(400).json({ error: 'El archivo es obligatorio' });
    }

    const connection = await mysql.createConnection(dbConfig);
    const [fichaExists] = await connection.execute("SELECT COUNT(*) AS count FROM ficha WHERE identificador = ?", [idFicha]);
    connection.end();

    if (fichaExists[0].count === 0) {
      return res.status(400).json({ error: "La ficha seleccionada no es válida" });
    }

    if (nombre && comentario && idFicha && idUsuario) {
      const connection = await mysql.createConnection(dbConfig);
      const fecha = new Date().toISOString().slice(0, 10); 

      const sql = `INSERT INTO horario (nombre, urlArchivo, comentario, fecha, idUsuario, idFicha)
                   VALUES (?, ?, ?, ?, ?, ?)`;

      await connection.execute(sql, [nombre, urlArchivo, comentario, fecha, idUsuario, idFicha]);
      connection.end();

      res.status(201).json({ message: 'Horario creado exitosamente' });
    } else {
      res.status(400).json({ error: 'Faltan campos obligatorios para crear el horario' });
    }
  } catch (error) {
    console.error('Error al crear el horario:', error);
    res.status(500).json({ error: 'Error al crear el horario' });
  }
});

// Ruta para actualizar un horario existente
app.put('/editarHorario/:identificador', async (req, res) => {
  try {
    const { nombre, comentario } = req.body;
    const { identificador } = req.params;

    if (nombre && comentario) {
      const connection = await mysql.createConnection(dbConfig);
      const sql = 'UPDATE horario SET nombre = ?, comentario = ? WHERE identificador = ?';
      await connection.execute(sql, [nombre, comentario, identificador]);
      connection.end();
      res.json({ message: 'Horario actualizado exitosamente' });
    } else {
      res.status(400).json({ error: 'Faltan campos obligatorios para actualizar el horario' });
    }
  } catch (error) {
    console.error('Error al actualizar el horario:', error);
    res.status(500).json({ error: 'Error al actualizar el horario' });
  }
});

// Ruta para eliminar un horario por su ID
app.delete('/eliminarHorario/:identificador', async (req, res) => {
  try {
    const { identificador } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    const sql = 'DELETE FROM horario WHERE identificador = ?';
    await connection.execute(sql, [identificador]);
    connection.end();
    res.json({ message: 'Horario eliminado exitosamente' });
  } catch (error) {
    console.error('Error al eliminar el horario:', error);
    res.status(500).json({ error: 'Error al eliminar el horario' });
  }
});

// ACTIVIDAD

// Ruta para crear una nueva actividad

app.post('/crearActividad', upload.single('archivo'), async (req, res) => {
  try {
    const { nombre, comentario, fechaInicio, fechaFinal, idUsuario, idFicha } = req.body;
    let urlArchivo = '';

    if (req.file) {
      urlArchivo = '/uploads/' + req.file.filename;
    } else {
      return res.status(400).json({ error: 'El archivo es obligatorio' });
    }

    const connection = await mysql.createConnection(dbConfig);
    const [fichaExists] = await connection.execute("SELECT COUNT(*) AS count FROM ficha WHERE identificador = ?", [idFicha]);
    connection.end();

    if (fichaExists[0].count === 0) {
      return res.status(400).json({ error: "La ficha seleccionada no es válida" });
    }

    if (nombre && comentario && fechaInicio && fechaFinal && idUsuario && idFicha) {
      const connection = await mysql.createConnection(dbConfig);
      const sql = `INSERT INTO guias (nombre, urlImagen, comentario, fechaInicio, fechaFinal, idUsuario, idFicha)
                   VALUES (?, ?, ?, ?, ?, ?, ?)`;
      await connection.execute(sql, [nombre, urlArchivo, comentario, fechaInicio, fechaFinal, idUsuario, idFicha]);
      connection.end();
      res.status(201).json({ message: 'Actividad creada exitosamente' });
    } else {
      res.status(400).json({ error: 'Faltan campos obligatorios para crear la actividad' });
    }
  } catch (error) {
    console.error('Error al crear la actividad:', error);
    res.status(500).json({ error: 'Error al crear la actividad' });
  }
})

// Ruta para obtener todas las actividades
app.get('/listarActividades/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;
    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT * FROM guias WHERE idUsuario = ?';
    const [rows] = await connection.execute(sql, [idUsuario]);
    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener las actividades:', error);
    res.status(500).json({ error: 'Error al obtener las actividades' });
  }
});

// Ruta para editar una actividad específica
app.put('/editarActividad/:identificador', async (req, res) => {
  try {
    const { nombre, comentario, fechaInicio, fechaFinal } = req.body;
    const { identificador } = req.params;

    if (nombre && comentario && fechaInicio && fechaFinal) {
      const connection = await mysql.createConnection(dbConfig);
      const sql = 'UPDATE guias SET nombre = ?, comentario = ?, fechaInicio = ?, fechaFinal = ? WHERE identificador = ?';
      await connection.execute(sql, [nombre, comentario, fechaInicio, fechaFinal, identificador]);
      connection.end();
      res.json({ message: 'Actividad actualizada exitosamente' });
    } else {
      res.status(400).json({ error: 'Faltan campos obligatorios para actualizar la actividad' });
    }
  } catch (error) {
    console.error('Error al actualizar la actividad:', error);
    res.status(500).json({ error: 'Error al actualizar la actividad' });
  }
});

// Ruta para eliminar una actividad por su ID
app.delete('/eliminarActividad/:identificador', async (req, res) => {
  try {
    const { identificador } = req.params;
    const connection = await mysql.createConnection(dbConfig);
    const sql = 'DELETE FROM guias WHERE identificador = ?';
    await connection.execute(sql, [identificador]);
    connection.end();
    res.json({ message: 'Actividad eliminada exitosamente' });
  } catch (error) {
    console.error('Error al eliminar la actividad:', error);
    res.status(500).json({ error: 'Error al eliminar la actividad' });
  }
});


//ASISTENCIA

// Ruta para crear una nueva entrada en la tabla asistencia si no existe para todos los aprendices asociados a la ficha seleccionada
app.post('/crearOActualizarAsistencia', async (req, res) => {
  try {
    const { fecha, idUsuario, idFicha } = req.body;
    const connection = await mysql.createConnection(dbConfig);

    // Obtener todos los aprendices asociados a la ficha seleccionada
    const aprendicesQuery = 'SELECT identificador FROM usuario WHERE idRol = 2 AND identificador IN (SELECT idUsuario FROM usuarioFicha WHERE idFicha = ?)';
    const [aprendicesRows] = await connection.execute(aprendicesQuery, [idFicha]);

    if (aprendicesRows.length === 0) {
      return res.status(200).json({ error: 'No se encontraron aprendices asociados a la ficha proporcionada' });
    }

    for (const aprendizRow of aprendicesRows) {
      const idAprendiz = aprendizRow.identificador;
      const sql = 'INSERT INTO asistencia (fecha, status, idFicha, idAprendiz, idInstructor) VALUES (?, ?, ?, ?, ?)';
      await connection.execute(sql, [fecha, 'Pendiente', idFicha, idAprendiz, idUsuario]);
    }

    connection.end();
    res.status(200).json({ message: 'Asistencia creada exitosamente' });
  } catch (error) {
    console.error('Error al crear la asistencia:', error);
    res.status(500).json({ error: 'Error al crear la asistencia' });
  }
});


// Ruta para marcar la asistencia de un usuario como asistió o no asistió
app.put('/marcarAsistencia/:identificador', async (req, res) => {
  try {
    const { status } = req.body; 
    const { identificador } = req.params;

    const connection = await mysql.createConnection(dbConfig);
    const sql = 'UPDATE asistencia SET status = ? WHERE identificador = ?';
    await connection.execute(sql, [status, identificador]); 
    connection.end();
    
    res.status(200).json({ message: 'Asistencia actualizada exitosamente' });
  } catch (error) {
    console.error('Error al actualizar la asistencia:', error);
    res.status(500).json({ error: 'Error al actualizar la asistencia' });
  }
});

// Ruta para editar una asistencia específica
app.put('/editarAsistencia/:identificador', async (req, res) => {
  try {
    const { status, fallaJustificada } = req.body; 
    const { identificador } = req.params;

    if (status !== undefined && fallaJustificada !== undefined) {
      const connection = await mysql.createConnection(dbConfig);
      const sql = 'UPDATE asistencia SET status = ?, fallaJustificada = ? WHERE identificador = ?';
      await connection.execute(sql, [status, fallaJustificada, identificador]);
      connection.end();
      res.json({ message: 'Asistencia actualizada exitosamente' });
    } else {
      res.status(400).json({ error: 'Faltan campos obligatorios para actualizar la asistencia' });
    }
  } catch (error) {
    console.error('Error al actualizar la asistencia:', error);
    res.status(500).json({ error: 'Error al actualizar la asistencia' });
  }
});

// Ruta para obtener usuarios con rol "Aprendiz" asociados a una ficha específica
app.get('/usuariosPorFicha', async (req, res) => {
  try {
    const { idFicha } = req.query;
    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT usuario.* FROM usuario INNER JOIN usuarioFicha ON usuario.identificador = usuarioFicha.idUsuario WHERE usuarioFicha.idFicha = ? AND usuario.idRol = 2';
    const [rows] = await connection.execute(sql, [idFicha]);
    connection.end();
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener los usuarios aprendices por ficha:', error);
    res.status(500).json({ error: 'Error al obtener los usuarios aprendices por ficha' });
  }
});

// Ruta para obtener la lista de asistencia filtrada por fecha, ficha e instructor
app.get('/listar', async (req, res) => {
  try {
    const { fecha, idFicha, idUsuario } = req.query;
    const connection = await mysql.createConnection(dbConfig);

    const sql = `SELECT asistencia.*, 
                        usuario.primerNombre AS nombreAprendiz, 
                        usuario.primerApellido AS primerApellidoAprendiz, 
                        usuario.segundoApellido AS segundoApellidoAprendiz, 
                        usuario.correo AS correoAprendiz 
                FROM asistencia 
                JOIN usuario ON asistencia.idAprendiz = usuario.identificador
                WHERE asistencia.fecha = ? AND asistencia.idFicha = ? AND asistencia.idInstructor = ?`;

    const [rows] = await connection.execute(sql, [fecha, idFicha, idUsuario]);
    connection.end();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener la lista de asistencia:', error);
    res.status(500).json({ error: 'Error al obtener la lista de asistencia' });
  }
});

// Ruta para obtener las fallas consecutivas de múltiples aprendices
app.post('/fallasConsecutivas', async (req, res) => {
  try {
    const { aprendicesIds } = req.body;
    console.log('Aprendices IDs:', aprendicesIds);

    const connection = await mysql.createConnection(dbConfig);

    const placeholders = aprendicesIds.map(() => '?').join(',');
    const sql = `SELECT idAprendiz, COUNT(*) AS fallasConsecutivas 
             FROM asistencia 
             WHERE idAprendiz IN (${placeholders}) AND status = 'No Asistió' 
             GROUP BY idAprendiz`;

    console.log('SQL Query:', sql);
    console.log('IDs de aprendices:', aprendicesIds);

    const [rows] = await connection.execute(sql, aprendicesIds);
    connection.end();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener las fallas consecutivas de múltiples aprendices:', error);
    res.status(500).json({ error: 'Error al obtener las fallas consecutivas de múltiples aprendices' });
  }
});


// Ruta para verificar si hay asistencia para la fecha y la ficha seleccionadas
app.get('/verificarAsistencia', async (req, res) => {
  try {
      const { fecha, idFicha, idUsuario } = req.query;
      const connection = await mysql.createConnection(dbConfig);

      const sql = 'SELECT * FROM asistencia WHERE fecha = ? AND idFicha = ? AND idInstructor = ?';
      const [rows] = await connection.execute(sql, [fecha, idFicha, idUsuario]);
      connection.end();
      res.status(200).json(rows.length > 0);
  } catch (error) {
      console.error('Error al verificar la asistencia:', error);
      res.status(500).json({ error: 'Error al verificar la asistencia' });
  }
});


// Ruta para obtener una asistencia por su identificador
app.get('/asistencia/:identificador', async (req, res) => {
  try {
    const { identificador } = req.params;
    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT * FROM asistencia WHERE identificador = ?';
    const [rows] = await connection.execute(sql, [identificador]);
    connection.end();

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No se encontró la asistencia con el identificador proporcionado' });
    }

    res.status(200).json(rows[0]);
  } catch (error) {
    console.error('Error al obtener la asistencia por identificador:', error);
    res.status(500).json({ error: 'Error al obtener la asistencia por identificador' });
  }
});

// Estadísticas

// Rutas para obtener estadísticas por fichas según el idUsuario del instructor
app.get('/estadisticasPorFichas/:idInstructor', async (req, res) => {
  try {
    const { idInstructor } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = `
      SELECT
        (SELECT COUNT(*) FROM blog WHERE idUsuario = ?) AS totalBlogs,
        (SELECT COUNT(*) FROM guias WHERE idUsuario = ?) AS totalActividades,
        (SELECT COUNT(*) FROM horario WHERE idUsuario = ?) AS totalHorarios,
        (SELECT COUNT(*) FROM asistencia WHERE idInstructor = ?) AS totalAsistencias
    `;
    const [results] = await connection.query(sql, [idInstructor, idInstructor, idInstructor, idInstructor]);
    connection.end();

    const { totalBlogs, totalActividades, totalHorarios, totalAsistencias } = results[0];
    const estadisticas = {
      totalBlogs,
      totalActividades,
      totalHorarios,
      totalAsistencias
    };
    res.status(200).json(estadisticas);
  } catch (error) {
    console.error('Error al obtener estadísticas por fichas:', error);
    res.status(500).json({ error: 'Error al obtener estadísticas por fichas' });
  }
});

// Rutas para obtener fichas por instructor según el idUsuario del instructor
app.get('/fichasPorInstructor/:idInstructor', async (req, res) => {
  try {
    const { idInstructor } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = `
      SELECT ficha.*
      FROM ficha
      JOIN usuarioFicha ON ficha.identificador = usuarioFicha.idFicha
      WHERE usuarioFicha.idUsuario = ?
    `;
    const [results] = await connection.query(sql, [idInstructor]);
    connection.end();

    res.status(200).json(results);
  } catch (error) {
    console.error('Error al obtener fichas por instructor:', error);
    res.status(500).json({ error: 'Error al obtener fichas por instructor' });
  }
});

// Ruta para obtener asistencias por ficha según el idFicha del instructor
app.get('/asistencias-por-ficha/:idInstructor/:idFicha', async (req, res) => {
  try {
    const { idInstructor, idFicha } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT COUNT(*) AS totalAsistencias FROM asistencia WHERE idInstructor = ? AND idFicha = ?';
    const [results] = await connection.query(sql, [idInstructor, idFicha]);
    connection.end();

    const { totalAsistencias } = results[0];
    const response = `En la ficha ${idFicha}: ${totalAsistencias} asistencias`;
    res.status(200).json({ message: response });
  } catch (error) {
    console.error('Error al obtener asistencias por ficha:', error);
    res.status(500).json({ error: 'Error al obtener asistencias por ficha' });
  }
});


// Rutas para obtener blogs según el idUsuario del instructor
app.get('/blogs/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT * FROM blog WHERE idUsuario = ?';
    const [results] = await connection.query(sql, [idUsuario]);
    connection.end(); // Cerrar la conexión después de la consulta

    res.status(200).json(results);
  } catch (error) {
    console.error('Error al obtener blogs:', error);
    res.status(500).json({ error: 'Error al obtener blogs' });
  }
});

// Rutas para obtener guías según el idUsuario del instructor
app.get('/guias/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT * FROM guias WHERE idUsuario = ?';
    const [results] = await connection.query(sql, [idUsuario]);
    connection.end(); // Cerrar la conexión después de la consulta

    res.status(200).json(results);
  } catch (error) {
    console.error('Error al obtener guías:', error);
    res.status(500).json({ error: 'Error al obtener guías' });
  }
});

// Rutas para obtener horarios según el idUsuario del instructor
app.get('/horarios/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT * FROM horario WHERE idUsuario = ?';
    const [results] = await connection.query(sql, [idUsuario]);
    connection.end(); // Cerrar la conexión después de la consulta

    res.status(200).json(results);
  } catch (error) {
    console.error('Error al obtener horarios:', error);
    res.status(500).json({ error: 'Error al obtener horarios' });
  }
});

// Rutas para obtener asistencias según el idUsuario del instructor
app.get('/asistencias/:idUsuario', async (req, res) => {
  try {
    const { idUsuario } = req.params;

    const connection = await mysql.createConnection(dbConfig);

    const sql = 'SELECT * FROM asistencia WHERE idInstructor = ?';
    const [results] = await connection.query(sql, [idUsuario]);
    connection.end();

    res.status(200).json(results);
  } catch (error) {
    console.error('Error al obtener asistencias:', error);
    res.status(500).json({ error: 'Error al obtener asistencias' });
  }
});

// KATALINA

// TRAER BLOG

app.get('/api/obtener-blog-por-correo/:correo', async (req, res) => {
  
  try {
    const correo = req.params.correo.replace(/"/g, ''); 
    const connection = await mysql.createConnection(dbConfig);
    const sql = `
      SELECT g.*, u.primerNombre, u.primerApellido
      FROM blog  g
      JOIN usuario u ON g.idUsuario = u.identificador
      WHERE g.idFicha = (
          SELECT idFicha
          FROM usuarioFicha
          WHERE idUsuario = (
              SELECT identificador AS idUsuario
              FROM usuario
              WHERE correo = ?
          )
      )`;

    const [rows] = await connection.execute(sql, [correo]);
    console.log('Correo recibido:', correo);


    connection.end();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener las blogs por correo:', error);
    res.status(500).json({ error: 'Error al obtener las blogs por correo' });
  }
});

// TRAER GUIAS
app.get('/api/obtener-guias-por-correo/:correo', async (req, res) => {
  try {
    const correo = req.params.correo.replace(/"/g, ''); 
    const connection = await mysql.createConnection(dbConfig);
    const sql = `
      SELECT g.*, u.primerNombre, u.primerApellido
      FROM guias g
      JOIN usuario u ON g.idUsuario = u.identificador
      WHERE g.idFicha = (
        SELECT idFicha
        FROM usuarioFicha
        WHERE idUsuario = (
          SELECT identificador AS idUsuario
          FROM usuario
          WHERE correo = ?
        )
      )`;

    const [rows] = await connection.execute(sql, [correo]);

    connection.end();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener las guías por correo:', error);
    res.status(500).json({ error: 'Error al obtener las guías por correo' });
  }
});

// // TRAER HORARIOS
app.get('/api/obtener-horarios-por-correo/:correo', async (req, res) => {
  try {
    const correo = req.params.correo.replace(/"/g, '');
    const connection = await mysql.createConnection(dbConfig);
    const sql = `
      SELECT h.*, u.primerNombre, u.primerApellido
      FROM horario h
      JOIN usuario u ON h.idUsuario = u.identificador
      WHERE h.idFicha = (
        SELECT idFicha
        FROM usuarioFicha
        WHERE idUsuario = (
          SELECT identificador AS idUsuario
          FROM usuario
          WHERE correo = ?
        )
      )`;

    const [rows] = await connection.execute(sql, [correo]);

    connection.end();

    res.status(200).json(rows);
  } catch (error) {
    console.error('Error al obtener horarios por correo:', error);
    res.status(500).json({ error: 'Error al obtener horarios por correo' });
  }
});


// ESTADISTICA ASISTENCIAS E INASISITENCIAS 
app.get("/api/asistenciasPorAprendiz/:correo", async (req, res) => {
  try {
    console.log('GRAFICO ASISTENCIA');
    const correo = req.params.correo.replace(/"/g, '');
    const connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(`
      SELECT status FROM asistencia 
      WHERE idAprendiz = (SELECT identificador FROM usuario WHERE correo = ?)
    `, [correo]);

    connection.end();

    // Mapea los resultados para obtener un array de objetos con la propiedad 'status'
    const formattedData = rows.map(row => ({ status: row.status }));

    res.status(200).json(formattedData);
  } catch (error) {
    console.error("Error al obtener las estadísticas de asistencias por aprendiz:", error);
    res.status(500).json({ error: "Error al obtener las estadísticas de asistencias por aprendiz" });
  }
});

// TABLA ASISTENCIA
app.get("/api/asistenciasPorcorreo/:correo", async (req, res) => {
  try {
    console.log('TABLA ASISTENCIA');
    const correo = req.params.correo.replace(/"/g, '');
    const connection = await mysql.createConnection(dbConfig);

    try {
      const [rows] = await connection.execute(`
        SELECT a.fecha, a.status, ui.primerNombre AS nombreInstructor
        FROM usuario u
        JOIN asistencia a ON u.identificador = a.idAprendiz
        JOIN usuario ui ON a.idInstructor = ui.identificador
        WHERE u.correo = ?;
      `, [correo]);

      const formattedData = rows.map(row => ({
        fecha: row.fecha,
        status: row.status,
        nombreInstructor: row.nombreInstructor
      }));

      res.status(200).json(formattedData);
    } catch (error) {
      console.error("Error al ejecutar la consulta SQL:", error);
      res.status(500).json({ error: "Error al ejecutar la consulta SQL" });
    } finally {
      await connection.end(); // Asegura que se cierre la conexión
    }
  } catch (error) {
    console.error("Error al conectar a la base de datos:", error);
    res.status(500).json({ error: "Error al conectar a la base de datos" });
  }
});

app.listen(port, () => {
  console.log(`Servidor en ejecución en http://localhost:${port}`);
});