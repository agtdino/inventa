# inventa
<h1> Inventario de equipos en red (frontend php crud + mysql) </h1>
<h2> Requisites </h2>
* mysql server (mariadb)
* apache2
* php
* nmap
* sudo 
<h2> VirtualHost configuration </h2>
.htaccess into inventa directory

<pre>
  RewriteEngine On
  RewriteBase /inventa/

  #Si el archivo o directorio no existe, redirige todo a index.php esta opción es importante.
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteRule ^(.*)$ index.php [L,QSA]
</pre>

<h2> Database creation</h2>
<h3> Equipos table </h3>
<pre>
  CREATE TABLE `equipos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(100) DEFAULT NULL,
  `ip` varchar(20) DEFAULT NULL,
  `ultima_vez_visto` datetime DEFAULT NULL,
  `mac` varchar(20) DEFAULT NULL,
  `dns` varchar(50) DEFAULT NULL,
  `vendor` varchar(55) DEFAULT NULL,
  `id_ou` int(11) DEFAULT NULL,
  `observaciones` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_uo` (`id_ou`),
  CONSTRAINT `equipos_ibfk_1` FOREIGN KEY (`id_ou`) REFERENCES `unidades_organizativas` (`id_ou`)
) ENGINE=InnoDB AUTO_INCREMENT=25 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci
</pre>

<h3> UO Unit Organizational table </h3>
<pre>
  CREATE TABLE `unidades_organizativas` (
  `id_ou` int(11) NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  PRIMARY KEY (`id_ou`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci
</pre>


<h2>Screen capture</h2>
<h3>Tables of database Inventa</h3>
<img width="720" height="156" alt="imagen" src="https://github.com/user-attachments/assets/1df75227-f4da-48f2-9647-5fab5413704b" />
<h3>Hostname list</h3>
<img width="720" height="841" alt="imagen" src="https://github.com/user-attachments/assets/81f2c254-0309-478a-bd05-7c5d7f52368f" />
<h3>UO Unit Organizative</h3>
<img width="720" height="291" alt="imagen" src="https://github.com/user-attachments/assets/0961eaf5-628b-4dc9-871b-882968e29e89" />



